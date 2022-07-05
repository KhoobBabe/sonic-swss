#include <cassert>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <exception>

#include "sai.h"
#include "macaddress.h"
#include "orch.h"
#include "request_parser.h"
#include "vrforch.h"
#include "vxlanorch.h"
#include "flowcounterrouteorch.h"
#include "directory.h"

using namespace std;
using namespace swss;

extern sai_virtual_router_api_t* sai_virtual_router_api;
extern sai_object_id_t gSwitchId;

extern Directory<Orch*>      gDirectory;
extern PortsOrch*            gPortsOrch;
extern FlowCounterRouteOrch* gFlowCounterRouteOrch;

// addOperation receives the request by-value from Request Class
// this adds a new opertion to the vector of operations
bool VRFOrch::addOperation(const Request& request)
{
    SWSS_LOG_ENTER(); // called
    uint32_t vni = 0; // vni is set to 0
    bool error = true;

    sai_attribute_t attr;
    vector<sai_attribute_t> attrs;

    // get the AttrFieldNames from the request
    for (const auto& name: request.getAttrFieldNames())
    {
        // get the value of the AttrFieldNames from the request

        // the attr.id is set to the respective state of the AttrFieldNames from the request
        if (name == "v4")
        {
            attr.id = SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V4_STATE;
            attr.value.booldata = request.getAttrBool("v4");
        }
        else if (name == "v6")
        {
            attr.id = SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V6_STATE;
            attr.value.booldata = request.getAttrBool("v6");
        }
        else if (name == "src_mac")
        {
            const auto& mac = request.getAttrMacAddress("src_mac");
            attr.id = SAI_VIRTUAL_ROUTER_ATTR_SRC_MAC_ADDRESS;
            memcpy(attr.value.mac, mac.getMac(), sizeof(sai_mac_t));
        }
        else if (name == "ttl_action")
        {
            attr.id = SAI_VIRTUAL_ROUTER_ATTR_VIOLATION_TTL1_PACKET_ACTION;
            attr.value.s32 = request.getAttrPacketAction("ttl_action");
        }
        else if (name == "ip_opt_action")
        {
            attr.id = SAI_VIRTUAL_ROUTER_ATTR_VIOLATION_IP_OPTIONS_PACKET_ACTION;
            attr.value.s32 = request.getAttrPacketAction("ip_opt_action");
        }
        else if (name == "l3_mc_action")
        {
            attr.id = SAI_VIRTUAL_ROUTER_ATTR_UNKNOWN_L3_MULTICAST_PACKET_ACTION;
            attr.value.s32 = request.getAttrPacketAction("l3_mc_action");
        }
        else if (name == "vni")
        {
            vni = static_cast<uint32_t>(request.getAttrUint(name));
            continue;
        }
        else if ((name == "mgmtVrfEnabled") || (name == "in_band_mgmt_enabled"))
        {
            SWSS_LOG_INFO("MGMT VRF field: %s ignored", name.c_str());
            continue;
        }
        else
        {
            SWSS_LOG_ERROR("Logic error: Unknown attribute: %s", name.c_str());
            continue;
        }
        attrs.push_back(attr);
    }

    const std::string& vrf_name = request.getKeyString(0); // get the vrf name which is present in the start of the request
    auto it = vrf_table_.find(vrf_name);                   // from the received vrf_name we search it in the vrf_table

    // if the vrf_name is not present in the table a new vrf is created
    if (it == std::end(vrf_table_))
    {
        // Create a new vrf
        sai_object_id_t router_id;
        sai_status_t status = sai_virtual_router_api->create_virtual_router(&router_id,
                                                                            gSwitchId,
                                                                            static_cast<uint32_t>(attrs.size()),
                                                                            attrs.data());

        // if the vrf cant be made
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("Failed to create virtual router name: %s, rv: %d", vrf_name.c_str(), status);
            task_process_status handle_status = handleSaiCreateStatus(SAI_API_VIRTUAL_ROUTER, status);
            if (handle_status != task_success)
            {
                return parseHandleSaiStatusFailure(handle_status);
            }
        }

        // setting values
        vrf_table_[vrf_name].vrf_id = router_id;
        vrf_table_[vrf_name].ref_count = 0;
        vrf_id_table_[router_id] = vrf_name;
        gFlowCounterRouteOrch->onAddVR(router_id);

        // if the vrf is created successfully
        if (vni != 0)
        {
            SWSS_LOG_INFO("VRF '%s' vni %d add", vrf_name.c_str(), vni);
            error = updateVrfVNIMap(vrf_name, vni);
            if (error == false)
            {
                return false;
            }
        }
        m_stateVrfObjectTable.hset(vrf_name, "state", "ok");
        SWSS_LOG_NOTICE("VRF '%s' was added", vrf_name.c_str());
    }

    // if the vrf already exists
    else
    {
        // Update an existing vrf

        sai_object_id_t router_id = it->second.vrf_id;

        for (const auto& attr: attrs)
        {
            sai_status_t status = sai_virtual_router_api->set_virtual_router_attribute(router_id, &attr);
            if (status != SAI_STATUS_SUCCESS)
            {
                SWSS_LOG_ERROR("Failed to update virtual router attribute. vrf name: %s, rv: %d", vrf_name.c_str(), status);
                task_process_status handle_status = handleSaiSetStatus(SAI_API_VIRTUAL_ROUTER, status);
                if (handle_status != task_success)
                {
                    return parseHandleSaiStatusFailure(handle_status);
                }
            }
        }

        // vrf's info is updated
        SWSS_LOG_INFO("VRF '%s' vni %d modify", vrf_name.c_str(), vni);

        // error detection
        error = updateVrfVNIMap(vrf_name, vni);
        if (error == false)
        {
            return false;
        }

        SWSS_LOG_NOTICE("VRF '%s' was updated", vrf_name.c_str());
    }

    return true;
}

// delOperation receives the request by-value from Request Class
// this deletes an opertion from the vector of operations
bool VRFOrch::delOperation(const Request& request)
{
    SWSS_LOG_ENTER();
    bool error = true;

    // getting the vrf name from the request
    const std::string& vrf_name = request.getKeyString(0);

    // if the vrf is not present in the table
    if (vrf_table_.find(vrf_name) == std::end(vrf_table_))
    {
        SWSS_LOG_ERROR("VRF '%s' doesn't exist", vrf_name.c_str());
        return true;
    }

    if (vrf_table_[vrf_name].ref_count)
        return false;

    sai_object_id_t router_id = vrf_table_[vrf_name].vrf_id;
    sai_status_t status = sai_virtual_router_api->remove_virtual_router(router_id);

    // if not able to remove the vrf
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to remove virtual router name: %s, rv:%d", vrf_name.c_str(), status);
        task_process_status handle_status = handleSaiRemoveStatus(SAI_API_VIRTUAL_ROUTER, status);
        if (handle_status != task_success)
        {
            return parseHandleSaiStatusFailure(handle_status);
        }
    }

    gFlowCounterRouteOrch->onRemoveVR(router_id);

    vrf_table_.erase(vrf_name);
    vrf_id_table_.erase(router_id);
    error = delVrfVNIMap(vrf_name, 0);
    if (error == false)
    {
        return false;
    }
    m_stateVrfObjectTable.del(vrf_name);

    // if the vrf is removed successfully
    SWSS_LOG_NOTICE("VRF '%s' was removed", vrf_name.c_str());

    return true;
}

// updateVrfVNIMap updates the vrf_vni_map_ with the vrf_name and vni
bool VRFOrch::updateVrfVNIMap(const std::string& vrf_name, uint32_t vni)
{
    SWSS_LOG_ENTER();
    uint32_t old_vni = 0;
    uint16_t vlan_id = 0;

    EvpnNvoOrch* evpn_orch = gDirectory.get<EvpnNvoOrch*>();           // getting the evpn_orch object
    VxlanTunnelOrch* tunnel_orch = gDirectory.get<VxlanTunnelOrch*>(); // getting the tunnel_orch object
    bool error = true;

    old_vni = getVRFmappedVNI(vrf_name); // getting the old vni from the vrf_vni_map_
    SWSS_LOG_INFO("VRF '%s' vni %d old_vni %d", vrf_name.c_str(), vni, old_vni);

    // if the vrf is not mapped to any vni
    if (old_vni != vni)
    {
        if (vni == 0)
        {
            error = delVrfVNIMap(vrf_name, old_vni);
            if (error == false)
            {
                return false;
            }
        }
        else
        {
            // update l3vni table, if vlan/vni is received later will be able to update L3VniStatus.
            l3vni_table_[vni].vlan_id = 0;
            l3vni_table_[vni].l3_vni = true;
            auto evpn_vtep_ptr = evpn_orch->getEVPNVtep(); // getting the evpn_vtep_ptr from the evpn_orch object
            if (!evpn_vtep_ptr)
            {
                SWSS_LOG_NOTICE("updateVrfVNIMap unable to find EVPN VTEP");
                return false;
            }

            vrf_vni_map_table_[vrf_name] = vni;             // updating the vrf_vni_map_ with the vrf_name and vni
            vlan_id = tunnel_orch->getVlanMappedToVni(vni); // getting the vlan_id from the tunnel_orch object
            l3vni_table_[vni].vlan_id = vlan_id;            // updating the l3vni_table_ with the vlan_id
            SWSS_LOG_INFO("addL3VniStatus vni %d vlan %d", vni, vlan_id);
            if (vlan_id != 0)
            {
                /*call VE UP*/
                error = gPortsOrch->updateL3VniStatus(vlan_id, true);
                SWSS_LOG_INFO("addL3VniStatus vni %d vlan %d, status %d", vni, vlan_id, error);
            }
        }
        SWSS_LOG_INFO("VRF '%s' vni %d map update", vrf_name.c_str(), vni);
    }

    return true;
}

// delVrfVNIMap deletes the vrf_vni_map_ with the vrf_name and vni
bool VRFOrch::delVrfVNIMap(const std::string& vrf_name, uint32_t vni)
{
    SWSS_LOG_ENTER();
    bool status = true;
    uint16_t vlan_id = 0;

    SWSS_LOG_INFO("VRF '%s' VNI %d map", vrf_name.c_str(), vni); // printing the vrf_name and vni

    // if the vrf is mapped to 0
    if (vni == 0)
    {
        vni = getVRFmappedVNI(vrf_name);
    }

    // for vni other than 0
    if (vni != 0)
    {
        vlan_id = l3vni_table_[vni].vlan_id; // getting the vlan_id from the l3vni_table_
        SWSS_LOG_INFO("delL3VniStatus vni %d vlan %d", vni, vlan_id);
        if (vlan_id != 0)
        {
            /*call VE Down*/
            status = gPortsOrch->updateL3VniStatus(vlan_id, false);
            SWSS_LOG_INFO("delL3VniStatus vni %d vlan %d, status %d", vni, vlan_id, status);
        }
        l3vni_table_.erase(vni);
        vrf_vni_map_table_.erase(vrf_name);
    }

    SWSS_LOG_INFO("VRF '%s' VNI %d map removed", vrf_name.c_str(), vni);
    return true;
}

// getVRFmappedVNI gets the vni from the vrf_vni_map_ with the vrf_name
int VRFOrch::updateL3VniVlan(uint32_t vni, uint16_t vlan_id)
{
    bool status = true;
    l3vni_table_[vni].vlan_id = vlan_id; // updating the l3vni_table_ with the vlan_id

    SWSS_LOG_INFO("updateL3VniStatus vni %d vlan %d", vni, vlan_id);
    /*call VE UP*/
    status = gPortsOrch->updateL3VniStatus(vlan_id, true); // calling the updateL3VniStatus function from the gPortsOrch object
    SWSS_LOG_INFO("updateL3VniStatus vni %d vlan %d, status %d", vni, vlan_id, status);

    return 0;
}
