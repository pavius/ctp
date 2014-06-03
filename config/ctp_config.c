/* 
 * Module message pool
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#include <string.h>
#include <arpa/inet.h>
#include <libxml/xmlreader.h>
#include "common/utils/assert.h"
#include "config/ctp_config_prv.h"
#include "modules/base/ctp_module_thread.h"
#include "modules/base/ctp_module_queue.h"
#include "modules/base/ctp_module_msgpool.h"
#include "modules/eth/ctp_mod_eth_rx.h"
#include "modules/eth/ctp_mod_eth_tx.h"
#include "modules/classifier/ctp_mod_classifier.h"
#include "modules/generator/ctp_mod_generator.h"
#include "modules/generator/ctp_mod_generator_flow.h"
#include "modules/util/ctp_mod_util_analyzer.h"
#include "modules/rlc/ctp_mod_rlc_seg.h"
#include "modules/rlc/ctp_mod_rlc_ras.h"
#include "modules/iub/ctp_mod_iub_encap.h"
#include "modules/iub/ctp_mod_iub_decap.h"
#include "modules/scheduler/ctp_mod_scheduler.h"

/****************************************************************************** 
    Parser
 *****************************************************************************/  

/* return an error */
rv_t ctp_config_element_error(xmlNode *err_node,
                              struct ctp_config_error *err_info,
                              const char *err_format)
{
    /* if data already exists in error, don't overwrite it */
    if (err_info->line == -1)
    {
        /* error */
        safe_strncpy(err_info->desc, 
                     err_format, 
                     sizeof(err_info->desc));

        /* set line */
        err_info->line = err_node ? err_node->line : -1;
    }

    /* return error */
    return RV_ERR_PARSE;
}

/* ignored node? */
bool ctp_config_allowed_ignored_node(const xmlNode *node)
{
    /* allow text and comment */
    return (xmlStrcmp(node->name, (xmlChar *)"text") == 0 ||
            xmlStrcmp(node->name, (xmlChar *)"comment") == 0);
}

/* get repeat count, if specified */
void ctp_config_get_element_repeat(xmlNode *element, unsigned int *repeat_count)
{
    xmlChar *value;

    /* parse value */
    value = xmlGetProp(element, (xmlChar *)"repeat");

    /* if there's a value */
    if (value)
    {
        /* try to convert value */
        if (str_to_uint((char *)value, repeat_count) != RV_OK)
        {
            /* got bad value */
            *repeat_count = 1;
        }

        /* free value */
        xmlFree(value);
    }
    else 
    {
        /* no repititions */
        *repeat_count = 1;
    }
}

/* parse ctp_config_mode */
rv_t ctp_config_read_value_config_mode(xmlNode *element, 
                                       enum ctp_config_mode *mode)
{
    xmlChar *value;
    rv_t result = RV_OK;

    /* parse value */
    value = xmlNodeListGetString(element->doc, element->xmlChildrenNode, 0);

    /* if there's a value */
    if (value)
    {
        /* check values */
        if      (xmlStrcmp(value, (xmlChar *)"rlc-iub-simulate") == 0)  *mode = CTP_CFG_MODE_RLC_IUB_SIMULATE;
        else if (xmlStrcmp(value, (xmlChar *)"rlc-iub") == 0)           *mode = CTP_CFG_MODE_RLC_IUB;
        else if (xmlStrcmp(value, (xmlChar *)"bridge") == 0)            *mode = CTP_CFG_MODE_BRIDGE;
        else if (xmlStrcmp(value, (xmlChar *)"bridge-via-tunnel") == 0) *mode = CTP_CFG_MODE_BRIDGE_VIA_TUNNEL;
        else if (xmlStrcmp(value, (xmlChar *)"scc") == 0)               *mode = CTP_CFG_MODE_SCC;
        else if (xmlStrcmp(value, (xmlChar *)"scc-simulate") == 0)      *mode = CTP_CFG_MODE_SCC_SIMULATE;
        else    result = RV_ERR;

        /* free value */
        xmlFree(value);
    }
    else result = RV_ERR;

    /* success */
    return result;
}

/* parse rx error schemes */
rv_t ctp_config_read_value_rx_err_scheme(xmlNode *element, enum ctp_log_rx_scheme *scheme)
{
    xmlChar *value;
    rv_t result = RV_OK;

    /* parse value */
    value = xmlNodeListGetString(element->doc, element->xmlChildrenNode, 0);

    /* if there's a value */
    if (value)
    {
        /* check values */
        if      (xmlStrcmp(value, (xmlChar *)"assert") == 0)  *scheme |= CTP_LOG_RX_SCHEME_ASSERT;
        else if (xmlStrcmp(value, (xmlChar *)"count") == 0)   *scheme |= CTP_LOG_RX_SCHEME_COUNT;
        else if (xmlStrcmp(value, (xmlChar *)"log") == 0)     *scheme |= CTP_LOG_RX_SCHEME_LOG;

        /* free value */
        xmlFree(value);
    }
    else result = RV_ERR;

    /* success */
    return result;
}

/* parse ctp_config_mode */
rv_t ctp_config_read_value_user_rlc_mode(xmlNode *element, enum ctp_config_rlc_mode *mode)
{
    xmlChar *value;
    rv_t result = RV_OK;

    /* parse value */
    value = xmlNodeListGetString(element->doc, element->xmlChildrenNode, 0);

    /* if there's a value */
    if (value)
    {
        /* check values */
        if      (xmlStrcmp(value, (xmlChar *)"um") == 0) *mode = CTP_CONFIG_RLC_MODE_UM;
        else if (xmlStrcmp(value, (xmlChar *)"am") == 0) *mode = CTP_CONFIG_RLC_MODE_AM;
        else    result = RV_ERR;

        /* free value */
        xmlFree(value);
    }
    else result = RV_ERR;

    /* success */
    return result;
}

/* parse ctp_config_mode */
rv_t ctp_config_read_value_fp_format(xmlNode *element, enum ctp_config_fp_format *format)
{
    xmlChar *value;
    rv_t result = RV_OK;

    /* parse value */
    value = xmlNodeListGetString(element->doc, element->xmlChildrenNode, 0);

    /* if there's a value */
    if (value)
    {
        /* check values */
        if      (xmlStrcmp(value, (xmlChar *)"hs") == 0) *format = CTP_CONFIG_FP_FORMAT_HS;
        else if (xmlStrcmp(value, (xmlChar *)"dch") == 0) *format = CTP_CONFIG_FP_FORMAT_DCH;
        else    result = RV_ERR;

        /* free value */
        xmlFree(value);
    }
    else result = RV_ERR;

    /* success */
    return result;
}

/* parse string */
rv_t ctp_config_read_value_string(xmlNode *element, 
                                  char *dest_str,
                                  const unsigned int dest_str_size)
{
    xmlChar *value;

    /* parse value */
    value = xmlNodeListGetString(element->doc, element->xmlChildrenNode, 0);

    /* if there's a value */
    if (value)
    {
        /* copy value */
        safe_strncpy(dest_str, (char *)value, dest_str_size);

        /* free value */
        xmlFree(value);
    }
    else return RV_ERR_PARSE;

    /* success */
    return RV_OK;
}

/* parse uint */
rv_t ctp_config_read_value_uint(xmlNode *element, 
                                const unsigned int repeat_index,
                                unsigned int *number)
{
    xmlChar *value, *parse_value;
    bool add_repitition;
    rv_t result;

    /* parse value */
    parse_value = value = xmlNodeListGetString(element->doc, element->xmlChildrenNode, 0);

    /* if there's a value */
    if (value)
    {
        /* check if number is in [x] format, indicating it should repeat  */
        add_repitition = ((value[0] == '[') && (value[strlen((char *)value) - 1] == ']'));

        /* check if this is auto-inc */
        if (add_repitition)
        {
            /* remove the parenthesis */
            value[strlen((char *)value) - 1] = '\0';

            /* skip first parenthesis */
            parse_value++;
        }
        
        /* copy value */
        result = str_to_uint((char *)parse_value, number);

        /* add repitition indx to number */
        if (add_repitition) *number += repeat_index;

        /* free value */
        xmlFree(value);
    }
    else result = RV_ERR_PARSE;

    /* success */
    return result;
}

/* parse short */
rv_t ctp_config_read_value_ushort(xmlNode *element, 
                                  const unsigned int repeat_index,
                                  unsigned short *number)
{
    unsigned int uint_value;

    /* use uint */
    rv_t result = ctp_config_read_value_uint(element, repeat_index, &uint_value);

    /* to short */
    *number = uint_value;

    /* return result */
    return result;
}

/* parse ip addr */
rv_t ctp_config_read_value_ip_addr(xmlNode *element, 
                                   const unsigned int repeat_index,
                                   unsigned int *ip_address)
{
    xmlChar *value, *parse_value;
    bool add_repitition;

    /* parse value */
    parse_value = value = xmlNodeListGetString(element->doc, element->xmlChildrenNode, 0);

    /* if there's a value */
    if (value)
    {
        /* check if number is in [x] format, indicating it should repeat  */
        add_repitition = ((value[0] == '[') && (value[strlen((char *)value) - 1] == ']'));

        /* check if this is auto-inc */
        if (add_repitition)
        {
            /* remove the parenthesis */
            value[strlen((char *)value) - 1] = '\0';

            /* skip first parenthesis */
            parse_value++;
        }

        /* copy value */
        inet_aton((char *)parse_value, (struct in_addr *)ip_address);

        /* keep ip_address in host order */
        *ip_address = ntohl(*ip_address);

        /* add repitition indx to ip */
        if (add_repitition) *ip_address = ip_addr_increment(*ip_address, repeat_index);

        /* free value */
        xmlFree(value);
    }
    else return RV_ERR_PARSE;

    /* success */
    return RV_OK;
}

/* write l2 header to tunnel */
rv_t ctp_config_write_tunnel_l2_header(const unsigned char *source_header,
                                       const unsigned int source_header_size,
                                       unsigned char **l2_header, 
                                       unsigned int *l2_header_left)
{
    /* add to l2 if there's room left */
    if (*l2_header_left >= source_header_size)
    {
        /* copy to location */
        memcpy(*l2_header, source_header, source_header_size);

        /* update pointers */
        *l2_header_left -= source_header_size;
        *l2_header      += source_header_size;

        /* return success */
        return RV_OK;
    }
    else
    {
        /* no more space */
        return RV_ERR;
    }
}

/* parse mpls header */
rv_t ctp_config_read_value_mpls(xmlNode *mpls_node, 
                                const unsigned int repeat_index,
                                unsigned char **l2_header, 
                                unsigned int *l2_header_left,
                                char *header_descriptor,
                                const unsigned int header_descriptor_size)
{
    unsigned int mpls_header, label, exp, s, ttl;
    xmlNode *node;
    rv_t result;

    /* init header */
    mpls_header = 0;

    /* iterate through the entities - parse elements as they come */
    for (node = mpls_node, result = RV_OK; node; node = node->next) 
    {
        /* start shoving values */
        if (xmlStrcmp(node->name, (xmlChar *)"label") == 0)
        {
            /* read value and set */
            result = ctp_config_read_value_uint(node, repeat_index, &label);
            mpls_header |= ((label & 0xFFFFF) << 12);
        }
        else if (xmlStrcmp(node->name, (xmlChar *)"exp") == 0)
        {
            /* read value and set */
            result = ctp_config_read_value_uint(node, repeat_index, &exp);
            mpls_header |= ((exp & 0x7) << 9);
        }
        else if (xmlStrcmp(node->name, (xmlChar *)"s") == 0)
        {
            /* read value and set */
            result = ctp_config_read_value_uint(node, repeat_index, &s);
            mpls_header |= ((s & 0x1) << 8);
        }
        else if (xmlStrcmp(node->name, (xmlChar *)"ttl") == 0)
        {
            /* read value and set */
            result = ctp_config_read_value_uint(node, repeat_index, &ttl);
            mpls_header |= (ttl & 0xFF);
        }
    }

    /* generate descriptor */
    snprintf(header_descriptor, header_descriptor_size - 1,
             "mpls(lbl:%d exp:%02x s:%s ttl:%d) ", 
             label, exp, s ? "yes" : "no", ttl);

    /* terminate it */
    header_descriptor[header_descriptor_size - 1] = '\0';

    /* to network */
    mpls_header = htonl(mpls_header);

    /* write l2 */
    return ctp_config_write_tunnel_l2_header((const unsigned char *)&mpls_header, 
                                             sizeof(mpls_header), 
                                             l2_header, 
                                             l2_header_left);
}

/* parse vlan header */
rv_t ctp_config_read_value_vlan(xmlNode *vlan_node, 
                                const unsigned int repeat_index,
                                unsigned char **l2_header, 
                                unsigned int *l2_header_left,
                                char *header_descriptor,
                                const unsigned int header_descriptor_size)
{
    unsigned int prio, cfi, id;
    unsigned short vlan_header;
    xmlNode *node;
    rv_t result;

    /* init header */
    vlan_header = 0;

    /* iterate through the entities - parse elements as they come */
    for (node = vlan_node, result = RV_OK; node; node = node->next) 
    {
        /* start shoving values */
        if (xmlStrcmp(node->name, (xmlChar *)"priority") == 0)
        {
            /* read value and set */
            result = ctp_config_read_value_uint(node, repeat_index, &prio);
            vlan_header |= ((prio & 0x7) << 13);
        }
        else if (xmlStrcmp(node->name, (xmlChar *)"cfi") == 0)
        {
            /* read value and set */
            result = ctp_config_read_value_uint(node, repeat_index, &cfi);
            vlan_header |= ((cfi & 0x1) << 12);
        }
        else if (xmlStrcmp(node->name, (xmlChar *)"id") == 0)
        {
            /* read value and set */
            result = ctp_config_read_value_uint(node, repeat_index, &id);
            vlan_header |= (id & 0xFFF);
        }
    }

    /* generate descriptor */
    snprintf(header_descriptor, header_descriptor_size - 1,
             "vlan(id:%d pri:%d cfi:%s) ", 
             id, prio, cfi ? "on" : "off");

    /* terminate it */
    header_descriptor[header_descriptor_size - 1] = '\0';

    /* to network */
    vlan_header = htons(vlan_header);

    /* write l2 */
    return ctp_config_write_tunnel_l2_header((const unsigned char *)&vlan_header, 
                                             sizeof(vlan_header), 
                                             l2_header, 
                                             l2_header_left);
}

/* parse vlan header */
rv_t ctp_config_read_value_raw(xmlNode *raw_node, 
                               const unsigned int repeat_index,
                               unsigned char **l2_header, 
                               unsigned int *l2_header_left,
                               char *header_descriptor,
                               const unsigned int header_descriptor_size)
{
    xmlChar *value;
    unsigned char raw_data[512];
    unsigned int raw_data_length;
    rv_t result;

    /* parse value */
    value = xmlNodeListGetString(raw_node->doc, raw_node->xmlChildrenNode, 0);

    /* if there's a value */
    if (value)
    {
        /* convert value */
        result = hex_str_to_byte_array((const char *)value, 
                                       (unsigned char *)&raw_data, 
                                       sizeof(raw_data), 
                                       &raw_data_length);
        /* success ? */
        if (result == RV_OK)
        {
            /* write to l2 */
            result = ctp_config_write_tunnel_l2_header((const unsigned char *)&raw_data, 
                                                       raw_data_length, 
                                                       l2_header, 
                                                       l2_header_left);
        }

        /* generate descriptor */
        snprintf(header_descriptor, header_descriptor_size - 1,
                 "raw(%s) ",
                 value);

        /* free value */
        xmlFree(value);
    }
    else return RV_ERR_PARSE;

    /* terminate it */
    header_descriptor[header_descriptor_size - 1] = '\0';

    /* success */
    return result;
}

/* parse the configuration node */
rv_t ctp_config_parse_global(struct ctp_config *config,
                             xmlNode *global_node,
                             struct ctp_config_error *err_info)
{
    xmlNode *node = NULL;
    rv_t result;

    /* iterate through the entities - parse elements as they come */
    for (node = global_node, result = RV_OK; node; node = node->next) 
    {
        /* try to write configuration fields */
        if (xmlStrcmp(node->name, (xmlChar *)"ds-mode") == 0)
            result = ctp_config_read_value_config_mode(node, &config->ds_mode);
        else if (xmlStrcmp(node->name, (xmlChar *)"us-mode") == 0)
            result = ctp_config_read_value_config_mode(node, &config->us_mode);
        else if (xmlStrcmp(node->name, (xmlChar *)"server-if") == 0)
            result = ctp_config_read_value_string(node, (char *)&config->server_if, sizeof(config->server_if));
        else if (xmlStrcmp(node->name, (xmlChar *)"client-if") == 0)
            result = ctp_config_read_value_string(node, (char *)&config->client_if, sizeof(config->client_if));
        else if (xmlStrcmp(node->name, (xmlChar *)"server-tunnel-if") == 0)
            result = ctp_config_read_value_string(node, (char *)&config->server_tunnel_if, sizeof(config->server_tunnel_if));
        else if (xmlStrcmp(node->name, (xmlChar *)"client-tunnel-if") == 0)
            result = ctp_config_read_value_string(node, (char *)&config->client_tunnel_if, sizeof(config->client_tunnel_if));
        else if (xmlStrcmp(node->name, (xmlChar *)"rx-err-scheme") == 0)
            result = ctp_config_read_value_rx_err_scheme(node, &config->rx_err_scheme);
        else if (!ctp_config_allowed_ignored_node(node))
            return ctp_config_element_error(node, err_info,
                                            "Unknown element name");

        /* break if result is not ok */
        if (result != RV_OK) break;
    }

    /* check if error */
    if (result != RV_OK)
    {
        /* failed to read an element */
        return ctp_config_element_error(node, err_info,
                                        "Invalid element value");
    }
    else return RV_OK;
}

/* parse the configuration node */
rv_t ctp_config_parse_module_scheduler(struct ctp_config *config,
                                       xmlNode *global_node,
                                       struct ctp_config_error *err_info)
{
    xmlNode *node = NULL;
    rv_t result;

    /* iterate through the entities - parse elements as they come */
    for (node = global_node, result = RV_OK; node; node = node->next) 
    {
        /* try to write configuration fields */
        if (xmlStrcmp(node->name, (xmlChar *)"max-user-leftover") == 0)
            result = ctp_config_read_value_uint(node, 0, &config->modules.scheduler.max_user_leftover);
        else if (xmlStrcmp(node->name, (xmlChar *)"max-common-leftover") == 0)
            result = ctp_config_read_value_uint(node, 0, &config->modules.scheduler.max_common_leftover);
        else if (!ctp_config_allowed_ignored_node(node))
            return ctp_config_element_error(node, err_info,
                                            "Unknown element name");

        /* break if result is not ok */
        if (result != RV_OK) break;
    }

    /* check if error */
    if (result != RV_OK)
    {
        /* failed to read an element */
        return ctp_config_element_error(node, err_info,
                                        "Invalid element value");
    }
    else return RV_OK;
}

/* parse the modules node */
rv_t ctp_config_parse_modules(struct ctp_config *config,
                              xmlNode *module_node,
                              struct ctp_config_error *err_info)
{
    xmlNode *node = NULL;
    rv_t result;

    /* iterate through the entities - parse elements as they come */
    for (node = module_node, result = RV_OK; 
          node; 
          node = node->next) 
    {
        /* iub encapsulation module config */
        if (xmlStrcmp(node->name, (xmlChar *)"scheduler") == 0)
        {
            /* parse scheduler config */
            result = ctp_config_parse_module_scheduler(config, node->children, err_info);
        }
        /* unknown entity */
        else if (!ctp_config_allowed_ignored_node(node))
        {
            /* return error */
            return ctp_config_element_error(node, err_info, 
                                            "Unknown element name");
        }
    }

    /* result */
    return result;
}

/* parse the configuration node */
rv_t ctp_config_read_value_gen_control(struct ctp_config_user *user,
                                       xmlNode *control_node,
                                       struct ctp_config_error *err_info)
{
    xmlNode *node = NULL;
    rv_t result;

    /* iterate through the entities - parse elements as they come */
    for (node = control_node, result = RV_OK; node; node = node->next) 
    {
        if (xmlStrcmp(node->name, (xmlChar *)"rate") == 0)
            result = ctp_config_read_value_uint(node, 0, &user->gen_control.rate);
        else if (xmlStrcmp(node->name, (xmlChar *)"min-size") == 0)
            result = ctp_config_read_value_uint(node, 0, &user->gen_control.min_size);
        else if (xmlStrcmp(node->name, (xmlChar *)"max-size") == 0)
            result = ctp_config_read_value_uint(node, 0, &user->gen_control.max_size);
        else if (!ctp_config_allowed_ignored_node(node))
            return ctp_config_element_error(node, err_info,
                                             "Unknown element name");

        /* break if result is not ok */
        if (result != RV_OK) break;
    }

    /* check if error */
    if (result != RV_OK)
    {
        /* failed to read an element */
        return ctp_config_element_error(node, err_info,
                                        "Invalid element value");
    }
    else return RV_OK;
}

/* parse the configuration node */
rv_t ctp_config_read_value_gen_traffic(struct ctp_config_user *user,
                                       xmlNode *control_node,
                                       struct ctp_config_error *err_info)
{
    xmlNode *node = NULL;
    rv_t result;

    /* iterate through the entities - parse elements as they come */
    for (node = control_node, result = RV_OK; node; node = node->next) 
    {
        if (xmlStrcmp(node->name, (xmlChar *)"rate") == 0)
            result = ctp_config_read_value_uint(node, 0, &user->gen_traffic.rate);
        else if (xmlStrcmp(node->name, (xmlChar *)"min-size") == 0)
            result = ctp_config_read_value_uint(node, 0, &user->gen_traffic.min_size);
        else if (xmlStrcmp(node->name, (xmlChar *)"max-size") == 0)
            result = ctp_config_read_value_uint(node, 0, &user->gen_traffic.max_size);
        else if (!ctp_config_allowed_ignored_node(node))
            return ctp_config_element_error(node, err_info,
                                             "Unknown element name");

        /* break if result is not ok */
        if (result != RV_OK) break;
    }

    /* check if error */
    if (result != RV_OK)
    {
        /* failed to read an element */
        return ctp_config_element_error(node, err_info,
                                        "Invalid element value");
    }
    else return RV_OK;
}

/* parse the configuration node */
rv_t ctp_config_read_value_err_injection(struct ctp_config_user *user,
                                         xmlNode *control_node,
                                         struct ctp_config_error *err_info)
{
    xmlNode *node = NULL;
    rv_t result;

    /* iterate through the entities - parse elements as they come */
    for (node = control_node, result = RV_OK; node; node = node->next) 
    {
        if (xmlStrcmp(node->name, (xmlChar *)"rate") == 0)
            result = ctp_config_read_value_uint(node, 0, &user->err_injection.rate);
        else if (xmlStrcmp(node->name, (xmlChar *)"all") == 0)                  
            user->err_injection.err_mask |= CTP_CONFIG_USER_ERR_ALL;
        else if (xmlStrcmp(node->name, (xmlChar *)"fp-bad-rlc-count") == 0)     
            user->err_injection.err_mask |= CTP_CONFIG_USER_ERR_FP_BAD_RLC_COUNT;
        else if (xmlStrcmp(node->name, (xmlChar *)"fp-bad-rlc-size") == 0)      
            user->err_injection.err_mask |= CTP_CONFIG_USER_ERR_FP_BAD_RLC_SIZE;
        else if (xmlStrcmp(node->name, (xmlChar *)"rlc-bad-seqnum") == 0)       
            user->err_injection.err_mask |= CTP_CONFIG_USER_ERR_RLC_BAD_SEQNUM;
        else if (xmlStrcmp(node->name, (xmlChar *)"rlc-not-enough-bytes") == 0) 
            user->err_injection.err_mask |= CTP_CONFIG_USER_ERR_RLC_NOT_ENOUGH_BYTES;
        else if (xmlStrcmp(node->name, (xmlChar *)"rlc-too-many-bytes") == 0)   
            user->err_injection.err_mask |= CTP_CONFIG_USER_ERR_RLC_TOO_MANY_BYTES;
        else if (!ctp_config_allowed_ignored_node(node))
            return ctp_config_element_error(node, err_info,
                                             "Unknown element name");

        /* break if result is not ok */
        if (result != RV_OK) break;
    }

    /* check if error */
    if (result != RV_OK)
    {
        /* failed to read an element */
        return ctp_config_element_error(node, err_info,
                                        "Invalid element value");
    }
    else return RV_OK;
}

/* parse the configuration node */
rv_t ctp_config_parse_user(struct ctp_config_tunnel *tunnel,
                           xmlNode *user_node,
                           const unsigned int repeat_index, 
                           struct ctp_config_error *err_info)
{
    xmlNode *node = NULL;
    rv_t result;

    /* create a user */
    struct ctp_config_user user;

    /* initialize the user */
    ctp_config_user_init(&user);

    /* iterate through the entities - parse elements as they come */
    for (node = user_node, result = RV_OK; node; node = node->next) 
    {
        /* try to write configuration fields */
        if (xmlStrcmp(node->name, (xmlChar *)"ip-addr") == 0)
        {
            unsigned int user_ip_address;

            /* get the user IP */
            result = ctp_config_read_value_ip_addr(node, repeat_index, &user_ip_address);

            /* set user ID to that of the two LSBs */
            user.id = (user_ip_address & 0xFFFF);

            /* and save the ip_addr, just for printing and stuff */
            user.ip_addr = user_ip_address;
        }
        else if (xmlStrcmp(node->name, (xmlChar *)"src-udp-port") == 0)
            result = ctp_config_read_value_ushort(node, repeat_index, &user.udp_header.source);
        else if (xmlStrcmp(node->name, (xmlChar *)"dst-udp-port") == 0)
            result = ctp_config_read_value_ushort(node, repeat_index, &user.udp_header.dest);
        else if (xmlStrcmp(node->name, (xmlChar *)"rlc-mode") == 0)
            result = ctp_config_read_value_user_rlc_mode(node, &user.rlc_mode);
        else if (xmlStrcmp(node->name, (xmlChar *)"rlc-frag-size") == 0)
            result = ctp_config_read_value_uint(node, repeat_index, &user.frag_payload_size);
        else if (xmlStrcmp(node->name, (xmlChar *)"fp-format") == 0)
            result = ctp_config_read_value_fp_format(node, &user.fp_header.format);
        else if (xmlStrcmp(node->name, (xmlChar *)"control-generator") == 0)
            result = ctp_config_read_value_gen_control(&user, node->children, err_info);
        else if (xmlStrcmp(node->name, (xmlChar *)"traffic-generator") == 0)
            result = ctp_config_read_value_gen_traffic(&user, node->children, err_info);
        else if (xmlStrcmp(node->name, (xmlChar *)"error-injection") == 0)
            result = ctp_config_read_value_err_injection(&user, node->children, err_info);
        else if (!ctp_config_allowed_ignored_node(node))
            return ctp_config_element_error(node, err_info,
                                             "Unknown element name");

        /* break if result is not ok */
        if (result != RV_OK) break;
    }

    /* check if error */
    if (result != RV_OK)
    {
        /* failed to read an element */
        return ctp_config_element_error(node, err_info,
                                        "Invalid element value");
    }
    else 
    {
        /* 
         * This code obviously needs to be in ctp_config_user_init
         */ 

        /* copy the temporary user to the place in the lookup */
        struct ctp_config_user *cfg_user = ctp_config_get_user_by_id(user.id);

        /* copy from temp to configuration user */
        memcpy(cfg_user, &user, sizeof(struct ctp_config_user));

        /* make sure we didn't go too far */
        ctp_assert(ctp_config_next_active_user_index < CTP_CONFIG_MAX_USERS, "Too many users");

        /* register ourselves into the active users array */
        ctp_config_active_users[ctp_config_next_active_user_index] = cfg_user;

        /* set index */
        cfg_user->index = ctp_config_next_active_user_index++;

        /* set tunnel */
        cfg_user->tunnel = tunnel;

        /* increment number of active users */
        ctp_config_active_users_count++;

        /* do post init */
        ctp_config_user_post_init(cfg_user);
            
        /* register user @ tunnel */
        ctp_config_tunnel_add_user(tunnel, cfg_user);

        /* sucess */
        return RV_OK;
    }
}

/* parse the configuration node */
rv_t ctp_config_parse_tunnel_transport(struct ctp_config_tunnel *tunnel,
                                       xmlNode *tunnel_transport_node,
                                       const unsigned int repeat_index,
                                       struct ctp_config_error *err_info)
{
    xmlNode *node = NULL;
    rv_t result;
    unsigned char *l2_header;
    unsigned int l2_header_left;
    char hdr_str[512];

    /* initialize the l2 header pointer - will be written sequentially */
    l2_header = tunnel->l2_header;
    l2_header_left = sizeof(tunnel->l2_header);

    /* iterate through the entities - parse elements as they come */
    for (node = tunnel_transport_node, result = RV_OK; node; node = node->next) 
    {
        /* init header string */
        memset(hdr_str, 0, sizeof(hdr_str));

        /* try to write configuration fields */
        if (xmlStrcmp(node->name, (xmlChar *)"mpls") == 0)
            result = ctp_config_read_value_mpls(node->children, repeat_index, &l2_header, &l2_header_left, hdr_str, sizeof(hdr_str));
        else if (xmlStrcmp(node->name, (xmlChar *)"vlan") == 0)
            result = ctp_config_read_value_vlan(node->children, repeat_index, &l2_header, &l2_header_left, hdr_str, sizeof(hdr_str));
        else if (xmlStrcmp(node->name, (xmlChar *)"raw") == 0)
            result = ctp_config_read_value_raw(node, repeat_index, &l2_header, &l2_header_left, hdr_str, sizeof(hdr_str));
        else if (!ctp_config_allowed_ignored_node(node))
            return ctp_config_element_error(node, err_info, 
                                            "Unknown element name");

        /* concat header string to tunnel descriptor */
        strncat(tunnel->l2_desc_string, 
                hdr_str, 
                sizeof(tunnel->l2_desc_string) - strlen(tunnel->l2_desc_string) - 1);

        /* break if result is not ok */
        if (result != RV_OK) break;
    }

    /* terminate descriptor string */
    tunnel->l2_desc_string[sizeof(tunnel->l2_desc_string) - 1] = '\0';

    /* check if error */
    if (result != RV_OK)
    {
        /* failed to read an element */
        return ctp_config_element_error(node, err_info,
                                        "Invalid element value");
    }
    else
    {
    	/* update how many bytes were written to tunnel l2 header */
    	tunnel->l2_header_length = (sizeof(tunnel->l2_header) - l2_header_left);

    	/* success */
    	return RV_OK;
    }
}

/* parse the configuration node */
rv_t ctp_config_parse_tunnel(struct ctp_config_nodeb *nodeb,
                             xmlNode *tunnel_node,
                             const unsigned int repeat_index,
                             struct ctp_config_error *err_info)
{
    xmlNode *node = NULL;
    rv_t result;
    unsigned int user_repeat_count;
    unsigned int user_repeat_index;

    /* create a tunnel */
    struct ctp_config_tunnel *tunnel = malloc(sizeof(struct ctp_config_tunnel));
        ctp_assert(tunnel != NULL, "Failed to allocate tunnel");
        bzero(tunnel, sizeof(struct ctp_config_tunnel));

    /* init tunnel */
    ctp_config_tunnel_init(tunnel);

    /* iterate through the entities - parse elements as they come */
    for (node = tunnel_node, result = RV_OK; node; node = node->next) 
    {
        /* try to write configuration fields */
        if (xmlStrcmp(node->name, (xmlChar *)"id") == 0)
            result = ctp_config_read_value_uint(node, repeat_index, &tunnel->id);
        else if (xmlStrcmp(node->name, (xmlChar *)"dscp") == 0)
            result = ctp_config_read_value_uint(node, repeat_index, &tunnel->dscp);
        else if (xmlStrcmp(node->name, (xmlChar *)"src-ip-addr") == 0)
            result = ctp_config_read_value_ip_addr(node, repeat_index, &tunnel->ip_header.saddr);
        else if (xmlStrcmp(node->name, (xmlChar *)"transport") == 0)
        {
        	/* tunnel transport */
            result = ctp_config_parse_tunnel_transport(tunnel, 
                                                       node->children,
                                                       repeat_index, 
                                                       err_info);
        }
        else if (xmlStrcmp(node->name, (xmlChar *)"user") == 0)
        {
            /* check if any repitions required */
            ctp_config_get_element_repeat(node, &user_repeat_count);

            /* create users as specified by repeat count */
            for (user_repeat_index = 0; user_repeat_index < user_repeat_count; ++user_repeat_index)
            {
                /* parse tunnel */
                result = ctp_config_parse_user(tunnel,
                                               node->children,
                                               user_repeat_index,
                                               err_info);

                /* break if result is not ok */
                if (result != RV_OK) break;
            }
        }
        else if (!ctp_config_allowed_ignored_node(node))
        {
            return ctp_config_element_error(node, err_info, 
                                             "Unknown element name");
        }

        /* break if result is not ok */
        if (result != RV_OK) break;
    }

    /* check if error */
    if (result != RV_OK)
    {
        /* failed to read an element */
        return ctp_config_element_error(node, err_info,
                                        "Invalid element value");
    }
    else 
    {
        /* increment number of active users */
        ctp_config_active_tunnels_count++;

        /* prepare everything in network order */
        tunnel->ip_header.saddr = htonl(tunnel->ip_header.saddr);
        tunnel->ip_header.daddr = htonl(tunnel->ip_header.daddr);

        /* set DSCP bits */
        tunnel->ip_header.tos = ((tunnel->dscp & 0xFF) << 2);

        /* set dest ip address in header */
        tunnel->ip_header.daddr = htonl(nodeb->ip_address);

        /* register tunnel @ nodeb */
        ctp_config_nodeb_add_tunnel(nodeb, tunnel);

        /* save nodeb in tunnel */
        tunnel->nodeb = nodeb;

        /* success */
        return RV_OK;
    }
}

/* parse the nodeb node */
rv_t ctp_config_parse_nodeb(struct ctp_config *config,
                            xmlNode *nodeb_node,
                            const unsigned int repeat_index,
                            struct ctp_config_error *err_info)
{
    xmlNode *node = NULL;
    rv_t result;

    /* create a nodeb */
    struct ctp_config_nodeb *nodeb = malloc(sizeof(struct ctp_config_nodeb));
        ctp_assert(nodeb != NULL, "Failed to allocate nodeb");
        bzero(nodeb, sizeof(struct ctp_config_nodeb));

    /* init nodeb */
    ctp_config_nodeb_init(nodeb);

    /* iterate through the entities - parse elements as they come */
    for (node = nodeb_node, result = RV_OK; node; node = node->next) 
    {
        /* try to write configuration fields */
        if (xmlStrcmp(node->name, (xmlChar *)"max-bandwidth") == 0)
            result = ctp_config_read_value_uint(node, repeat_index, &nodeb->max_bandwidth_bps);
        else if (xmlStrcmp(node->name, (xmlChar *)"ip-address") == 0)
            result = ctp_config_read_value_ip_addr(node, repeat_index, &nodeb->ip_address);
        else if (xmlStrcmp(node->name, (xmlChar *)"tunnel") == 0)
        {
            result = ctp_config_parse_tunnel(nodeb, 
                                             node->children,
                                             repeat_index, 
                                             err_info);
        }
        else if (!ctp_config_allowed_ignored_node(node))
        {
            /* error */
            return ctp_config_element_error(node, err_info, "Unknown element name");
        }

        /* break if result is not ok */
        if (result != RV_OK) break;
    }

    /* check if error */
    if (result != RV_OK)
    {
        /* failed to read an element */
        return ctp_config_element_error(node, err_info,
                                        "Invalid element value");
    }
    else 
    {
        /* increment number of active users */
        ctp_config_active_nodeb_count++;

        /* init nodeb */
        ctp_config_nodeb_post_config_init(nodeb);

        /* register nodeb @ config */
        ctp_config_nodeb_add(nodeb);

        /* success */
        return RV_OK;
    }
}

/* parse the topology node */
rv_t ctp_config_parse_topology(struct ctp_config *config,
                               xmlNode *config_element,
                               struct ctp_config_error *err_info)
{
    xmlNode *node = NULL;
    rv_t result;
    unsigned int repeat_count, repeat_index;

    /* iterate through the entities - parse elements as they come */
    for (node = config_element, result = RV_OK; 
          node; 
          node = node->next) 
    {
        /* iub encapsulation module config */
        if (xmlStrcmp(node->name, (xmlChar *)"node-b") == 0)
        {
            /* check if any repitions required */
            ctp_config_get_element_repeat(node, &repeat_count);

            /* create tunnels as specified by repeat count */
            for (repeat_index = 0; repeat_index < repeat_count; ++repeat_index)
            {
                /* parse nodeb */
                result = ctp_config_parse_nodeb(config, 
                                                node->children,
                                                repeat_index,
                                                err_info);

                /* break if result is not ok */
                if (result != RV_OK) break;
            }
        }
        /* unknown entity */
        else if (!ctp_config_allowed_ignored_node(node))
        {
            /* return error */
            return ctp_config_element_error(node, err_info,
                                            "Unknown element name");
        }

        /* break if result is not ok */
        if (result != RV_OK) break;
    }

    /* result */
    return result;
}

/* parse the configuration node */
rv_t ctp_config_parse_configuration(struct ctp_config *config,
                                    xmlNode *config_element,
                                    struct ctp_config_error *err_info)
{
    xmlNode *node = NULL;
    rv_t result;

    /* iterate through the entities - parse elements as they come */
    for (node = config_element, result = RV_OK; 
          node && result == RV_OK; 
          node = node->next) 
    {
        /* global config */
        if (xmlStrcmp(node->name, (xmlChar *)"global") == 0)
        {
            /* parse and set result */
            result = ctp_config_parse_global(config, 
                                             node->children, 
                                             err_info);

        }
        /* module configuration */
        else if (xmlStrcmp(node->name, (xmlChar *)"modules") == 0)
        {
            /* parse and set result */
            result = ctp_config_parse_modules(config, 
                                              node->children, 
                                              err_info);
        }
        /* topology configuration */
        else if (xmlStrcmp(node->name, (xmlChar *)"topology") == 0)
        {
            /* parse and set result */
            result = ctp_config_parse_topology(config, 
                                               node->children, 
                                               err_info);
        }
        /* unknown entity */
        else if (!ctp_config_allowed_ignored_node(node))
        {
            /* return error */
            return ctp_config_element_error(node, err_info, 
                                            "Unknown element name");
        }
    }

    /* result */
    return result;
}

/* apply the document */
rv_t ctp_config_parse_doc_to_config(struct ctp_config *config,
                                    xmlDoc *doc, 
                                    struct ctp_config_error *err_info)
{
    xmlNode *root_element   = NULL;
    xmlNode *node   = NULL;
    rv_t result;

    /* Get the root element node */
    root_element = xmlDocGetRootElement(doc);

    /* iterate through the entities - must onyl be "configuration" */
    for (node = root_element, result = RV_OK; 
          node && result == RV_OK; 
          node = node->next) 
    {
        /* get the name */
        if (xmlStrcmp(node->name, (xmlChar *)"configuration") == 0)
        {
            /* parse a configuration element */
            result = ctp_config_parse_configuration(config,
                                                    node->children,
                                                    err_info);
        }
        else
        {
            /* return the parser error */
            return ctp_config_element_error(node, err_info, 
                                            "Root node may only contain a 'configuration' node");
        }
    }

    /* 
     * Post parse checks
     */

    /* make sure we have at least one handling mechanism for rx errors */
    if (result == RV_OK && ctp_configuration.rx_err_scheme == 0)
    {
        /* set node error */
        result = ctp_config_element_error(NULL, err_info, 
                                          "rx-err-scheme must be at least one of assert, count or log");
    }

    /* success */
    return result;
}

/****************************************************************************** 
    Configuration chains
 *****************************************************************************/  

/* create pools */
void ctp_config_init_chain(struct ctp_config_chain *chain)
{
    unsigned int pool_idx;
    rv_t result;

    /* allocate sdu pool - this pool holds buffers for data that is received from the ethernet and
     * for Iub frames that are being built from PDUs
     */
    ctp_module_msgpool_create(1800, 100 * 1000, &chain->sdu_pool);

    /* per-message overhead */
    const unsigned int per_pdu_overhead = 3 +                                   /* RLC max header */
                                          sizeof(struct ctp_buffer_header);     /* buffer header  */

    /* define pdu pools */
    struct
    {
        unsigned int data_size; /* header + payload */
        unsigned int count;     /* # of pdus */

    } ctp_config_pdu_pools[] =
    {
        /* must be in ascending order (we search for the smallest pool which the data can fit in) */
        {40 + per_pdu_overhead, 50 * 1000 * 1000},
        {80 + per_pdu_overhead, 1 * 1000 * 1000},
    };

    /* verify enough pools */
    ctp_assert(array_size(ctp_config_pdu_pools) <= array_size(chain->pdu_pools), 
               "Not enough space for PDU pools");

    /* allocate pdu pools */
    for (pool_idx = 0; pool_idx < array_size(ctp_config_pdu_pools); ++pool_idx)
    {
        /* allocate the pool according to the global config */
        result = ctp_bufpool_create(ctp_config_pdu_pools[pool_idx].data_size, 
                                    ctp_config_pdu_pools[pool_idx].count, 
                                    NULL, NULL,
                                    &chain->pdu_pools[pool_idx].pool);

        /* */
        ctp_assert(result == RV_OK, "Failed to allocate %d buffers of %d bytes",
                   ctp_config_pdu_pools[pool_idx].count, ctp_config_pdu_pools[pool_idx].data_size);

        /* save info */
        chain->pdu_pools[pool_idx].data_size = ctp_config_pdu_pools[pool_idx].data_size;
        chain->pdu_pools[pool_idx].count = ctp_config_pdu_pools[pool_idx].count;
    }

    /* set pool count */
    chain->pdu_pool_count = array_size(ctp_config_pdu_pools);
}

/* TODO */
#define ctp_config_chain_verify_step(desc)                  \
    if (result != RV_OK)                                    \
    {                                                       \
        printf("Failed %s\n", desc);                        \
        goto err_chain;                                     \
    }

/* start a module with an attached thread */
rv_t ctp_config_chain_start_module_thread(handle_t module)
{
    struct ctp_module *the_module = (struct ctp_module *)module;

    /* start the thread */
    return ctp_module_thread_start(the_module->thread);
}

/* start a module with an attached thread and queue */
rv_t ctp_config_chain_start_module_queue_thread(handle_t module)
{
    /* get the queue */
    struct ctp_module *queue_module = ((struct ctp_module *)module)->input;

    /* start the thread attached to the queue */
    return ctp_module_thread_start(queue_module->thread);
}

/* create a module with an attached thread */
rv_t ctp_config_chain_create_module_thread(handle_t attached_module,
                                           const int scheduling_mode,
                                           const int scheduling_priority,
                                           const int core_affinity,
                                           handle_t *thread_handle)
{
    handle_t some_thread;
    rv_t result = RV_ERR;

    /* create the thread */
    if (ctp_module_thread_create(scheduling_mode, scheduling_priority, 
                                 core_affinity, &some_thread) == RV_OK)
    {
        /* check if we need to register a module */
        if (attached_module) 
            result = ctp_module_thread_attach_module(some_thread, attached_module);
    }

    /* return the thread handle is success */
    if (thread_handle && result == RV_OK) *thread_handle = some_thread;

    /* failed */
    return result;
}

/* create a module queue with an attached thread, and have the thread run the queue poll() */
rv_t ctp_config_chain_create_module_queue_thread(handle_t attached_module,
                                                 const int scheduling_mode,
                                                 const int scheduling_priority,
                                                 const int core_affinity,
                                                 handle_t *thread_handle)
{
    handle_t some_queue, module_to_attach_to;

    /* create queue */
    ctp_module_queue_create(&some_queue);

    /* attach it */
    ctp_module_queue_attach_module(some_queue, attached_module);

    /* create thread for the queue */
    ctp_config_chain_create_module_thread(some_queue, scheduling_mode, scheduling_priority, 
                                          core_affinity, thread_handle);

    /* ok for now */
    return RV_OK;
}

/* create flows for control and traffic according to configuration */
rv_t ctp_config_chain_init_generator_flows(handle_t traffic_gen, handle_t control_gen)
{
    /* constants */
    const char *eth_src = "\x00\x01\x02\x04\x05\x06",
               *eth_dst = "\x00\x0a\x0b\x0c\x0d\x0e";
    unsigned int user_idx, ip_src = inet_addr("100.100.100.100");

    /* iterate over users and see if they need control packets generator */
    for (user_idx = 0; user_idx <= (CTP_CONFIG_MAX_USERS - 1); ++user_idx)
    {
        /* get the user */
        struct ctp_config_user *user = ctp_config_get_user_by_id(user_idx);

        /* is user configured? */
        if (user->active)
        {
            /* do we need to generate control for this user? */
            if (user->gen_control.rate != 0)
            {
                /* create a control flow */
                ctp_mod_generator_flow_create_control(control_gen, user, 
                                                      user->gen_control.rate, 
                                                      user->gen_control.min_size, 
                                                      user->gen_control.max_size);
            }

            /* do we need to generate traffic for this user? */
            if (user->gen_traffic.rate != 0)
            {
                /* create a control flow */
                ctp_mod_generator_flow_create_ipv4_udp(traffic_gen, eth_src, eth_dst, 
                                                       htonl(ip_src), user->ip_addr, 
                                                       100, 200,   
                                                       user->gen_traffic.rate,      
                                                       user->gen_traffic.min_size,     
                                                       user->gen_traffic.max_size);
            }
        }
    }

    /* success */
    return RV_OK;
}

/* ingress rx to tunnel tx */
rv_t ctp_config_chain_ingress_rx_to_tunnel_tx(struct ctp_config *config,
                                              handle_t *chain_head, 
                                              handle_t *chain_tail,
                                              handle_t *scheduler,
                                              handle_t *control_generator)
{
    handle_t ingress_classifier, rlc_seg, iub_encap; 
    user_id_t user_idx;
    unsigned int pdu_pool_idx;
    rv_t result;
    
    /* 
     * Create modules
     */ 

    /* create ethertype search pattern */
    const struct ctp_mod_classifier_pattern ethetype_pattern = 
    {
        .offset     = 12,
        .size       = 2,
        .mode       = CTP_MOD_CLASSIFIER_PM_MUST_MATCH,
        .data       = 
        {
            0x08, 
            0x00
        },
    };

    /* create classifier */
    ctp_mod_classifier_create("DS Srv", 
                              CTP_MOD_CLASSIFIER_SP_HEAD, /* search user-id from head */
                              14 + 18,                    /* skip ethernet and then offset into IP */
                              &ethetype_pattern, 1,
                              &ingress_classifier);

    /* create rlc segmentation module */
    ctp_mod_rlc_seg_create(&rlc_seg);

    /* register pdu pool @ rlc-seg */
    for (pdu_pool_idx = 0; pdu_pool_idx < config->chain.pdu_pool_count; ++pdu_pool_idx)
    {
        /* register the pdu pool */
        ctp_mod_rlc_seg_register_pdu_pool(rlc_seg, 
                                          config->chain.pdu_pools[pdu_pool_idx].pool,
                                          config->chain.pdu_pools[pdu_pool_idx].data_size);
    }

    /* create the scheduler */
    ctp_mod_scheduler_create("scheduler", config->chain.sdu_pool, 
                             config->modules.scheduler.max_user_leftover,
                             config->modules.scheduler.max_common_leftover,
                             scheduler);

    /* create the control generator */
    ctp_mod_generator_create(control_generator, "Control Gen", config->chain.sdu_pool);

    /* create the iub encapsulation */
    ctp_mod_iub_encap_create(&iub_encap);

    /* 
     * Connect the modules
     */ 

    /* ingress classifier -> rlc seg dynamically bound */

    /* rlc seg -> iub encap (for control frames only, data goes through queues) */
    ctp_module_set_output(rlc_seg, iub_encap);

    /* control generator -> iub_encap */
    ctp_module_set_output(*control_generator, iub_encap);

    /* scheduler -> iub encap */
    ctp_module_set_output(*scheduler, iub_encap);

    /* 
     * Bind users to their classifier
     */

    /* iterate over users */
    for (user_idx = 0; user_idx <= (CTP_CONFIG_MAX_USERS - 1); ++user_idx)
    {
        /* if user was configured, bind to rlc_seg */
        if (ctp_config_get_user_by_id(user_idx)->active)
        {
            /* bind classifiers */
            ctp_mod_classifier_bind_user_handler(ingress_classifier, 
                                                 ctp_config_get_user_by_id(user_idx), 
                                                 rlc_seg);
        }
    }

    /* return chain head and tail */
    *chain_head = ingress_classifier;
    *chain_tail = iub_encap;

    /* success */
    return RV_OK;

/* error */
err_chain:
    return result;
}

/* tunnel rx to egress tx */
rv_t ctp_config_chain_tunnel_rx_to_egress_tx(struct ctp_config *config,
                                             handle_t *chain_head, 
                                             handle_t *chain_tail)
{
    handle_t tunnel_classifier, iub_decap, rlc_ras;
    user_id_t user_idx;

    /* 
     * Create modules
     */ 

    /* look for CTP_MOD_IUB_CLASSIFIED_FRAME_MAGIC */
    const struct ctp_mod_classifier_pattern classified_frame_magic_pattern = 
    {
        .offset     = 0,
        .size       = 4,
        .mode       = CTP_MOD_CLASSIFIER_PM_MUST_MATCH,
        .data       = 
        {   
            (CTP_MOD_IUB_CLASSIFIED_FRAME_MAGIC >> 24) & 0xFF, 
            (CTP_MOD_IUB_CLASSIFIED_FRAME_MAGIC >> 16) & 0xFF,
            (CTP_MOD_IUB_CLASSIFIED_FRAME_MAGIC >> 8)  & 0xFF,
            (CTP_MOD_IUB_CLASSIFIED_FRAME_MAGIC >> 0)  & 0xFF
        },
    };

    /* create tunnel classifier */
    ctp_mod_classifier_create("DS Cln", 
                              CTP_MOD_CLASSIFIER_SP_HEAD,           /* search from head */
                              4,                                    /* 2 bytes after beginning of frame */ 
                              &classified_frame_magic_pattern,
                              1,
                              &tunnel_classifier);

    /* create iub decapsulation */
    ctp_mod_iub_decap_create(&iub_decap);

    /* create rlc reassembly module */
    ctp_mod_rlc_ras_create(config->chain.sdu_pool, &rlc_ras);

    /* 
     * Connect the modules
     */ 

    /* tunnel classifier -> iub decap dynamically bound */

    /* iub decap -> rlc reassembly */
    ctp_module_set_output(iub_decap, rlc_ras);

    /* 
     * Bind users to their classifier
     */

    /* iterate over users */
    for (user_idx = 0; user_idx < CTP_CONFIG_MAX_USERS; ++user_idx)
    {
        /* if user was configured, bind to rlc_seg */
        if (ctp_config_get_user_by_id(user_idx)->active)
        {
            /* bind classifiers */
            ctp_mod_classifier_bind_user_handler(tunnel_classifier, 
                                                 ctp_config_get_user_by_id(user_idx), 
                                                 iub_decap);
        }
    }

    /* return chain head and tail */
    *chain_head = tunnel_classifier;
    *chain_tail = rlc_ras;

    /* success */
    return RV_OK;
}

/* upstream bridging */
rv_t ctp_config_chain_upstream_bridge(struct ctp_config *config, 
                                      handle_t shared_thread)
{
    rv_t result;
    handle_t up_eth_ingress_rx_thread, up_eth_ingress_rx,
             up_eth_egress_tx;

    /**************************************************************************
     * Upstream (bypass)
     ************************************************************************ */

    /* 
     * Create modules
     */ 

    /* create up ingress rx */
    result = ctp_mod_eth_rx_create(config->chain.sdu_pool, "US Cln", config->client_if, &up_eth_ingress_rx);
    ctp_config_chain_verify_step("Creating up client interface");

    /* create up egress tx */
    result = ctp_mod_eth_tx_create("US Srv", config->server_if, &up_eth_egress_tx);
    ctp_config_chain_verify_step("Creating up server interface");

    /* 
     * Connect the modules: 
     */ 

    /* ingress rx -> egress tx */
    ctp_module_set_output(up_eth_ingress_rx, up_eth_egress_tx);

    /* 
     * Create and run the thread
     */ 

    /* creates thread */
    ctp_module_thread_attach_module(shared_thread, up_eth_ingress_rx);

    /* success */
    return RV_OK;

/* error */
err_chain:
    return result;
}

/* upstream bridging */
rv_t ctp_config_chain_upstream_bridge_via_tunnel(struct ctp_config *config, 
                                                 handle_t shared_thread)
{
    rv_t result;
    handle_t up_eth_client_thread, up_eth_client, up_eth_client_tunnel,
             up_eth_server_tunnel_thread, up_eth_server_tunnel, up_eth_server;

    /**************************************************************************
     * Upstream (bypass)
     ************************************************************************ */

    /* 
     * Create modules
     */ 

    /* create up client eth */
    result = ctp_mod_eth_rx_create(config->chain.sdu_pool, "US Cln", config->client_if, &up_eth_client);
    ctp_config_chain_verify_step("Creating up client interface");

    /* create up client tunnel eth  */
    result = ctp_mod_eth_tx_create("US Cln tnl", config->client_tunnel_if, &up_eth_client_tunnel);
    ctp_config_chain_verify_step("Creating up client tunnel interface");

    /* create up server eth */
    result = ctp_mod_eth_rx_create(config->chain.sdu_pool, "US Srv tnl", config->server_tunnel_if, &up_eth_server_tunnel);
    ctp_config_chain_verify_step("Creating up server interface");

    /* create up server eth */
    result = ctp_mod_eth_tx_create("US Srv", config->server_if, &up_eth_server);
    ctp_config_chain_verify_step("Creating up server interface");

    /* 
     * Connect the modules: 
     */ 

    /* client eth -> client tunnel eth */
    ctp_module_set_output(up_eth_client, up_eth_client_tunnel);

    /* server tunnel eth -> server eth */
    ctp_module_set_output(up_eth_server_tunnel, up_eth_server);

    /* 
     * Create and run the thread
     */ 

    /* attach to shared thread */
    ctp_module_thread_attach_module(shared_thread, up_eth_server_tunnel);
    ctp_module_thread_attach_module(shared_thread, up_eth_client);

    /* success */
    return RV_OK;

/* error */
err_chain:
    return result;
}

/* downstream bridging */
rv_t ctp_config_chain_downstream_bridge_via_tunnel(struct ctp_config *config, 
                                                   handle_t shared_thread)
{
    rv_t result;
    handle_t down_eth_client_tunnel_thread, down_eth_client, down_eth_client_tunnel,
             down_eth_server_thread, down_eth_server_tunnel, down_eth_server;

    /**************************************************************************
     * Downstream (bypass)
     ************************************************************************ */

    /* 
     * Create modules
     */ 

    /* create down server eth */
    result = ctp_mod_eth_rx_create(config->chain.sdu_pool, "DS Srv", config->server_if, &down_eth_server);
    ctp_config_chain_verify_step("Creating down server interface");

    /* create down server tunnel eth  */
    result = ctp_mod_eth_tx_create("DS Srv tnl", config->server_tunnel_if, &down_eth_server_tunnel);
    ctp_config_chain_verify_step("Creating down server tunnel interface");

    /* create down tunnel client eth */
    result = ctp_mod_eth_rx_create(config->chain.sdu_pool, "DS Cln tnl", config->client_tunnel_if, &down_eth_client_tunnel);
    ctp_config_chain_verify_step("Creating down client tunnel interface");

    /* create up server eth */
    result = ctp_mod_eth_tx_create("DS Cln", config->client_if, &down_eth_client);
    ctp_config_chain_verify_step("Creating up client interface");

    /* 
     * Connect the modules: 
     */ 

    /* server eth -> server tunnel eth */
    ctp_module_set_output(down_eth_server, down_eth_server_tunnel);

    /* client tunnel eth -> client eth */
    ctp_module_set_output(down_eth_client_tunnel, down_eth_client);

    /* 
     * Create and run the thread
     */ 

    /* attach to shared thread */
    ctp_module_thread_attach_module(shared_thread, down_eth_server);
    ctp_module_thread_attach_module(shared_thread, down_eth_client_tunnel);

    /* success */
    return RV_OK;

/* error */
err_chain:
    return result;
}

/* eth -> seg -> iub -> ras -> eth */
rv_t ctp_config_chain_downstream_rlc_iub(struct ctp_config *config, 
                                         handle_t shared_thread)
{
    rv_t result;
    handle_t down_eth_server, down_eth_server_thread, down_eth_tunnel_server,
             down_eth_client, down_eth_tunnel_client,
             down_server_classifier, down_server_iub_encap,
             down_client_classifier, down_client_rlc_ras,
             down_server_scheduler,
             traffic_gen, control_gen;

    /**************************************************************************
     * Downstream (via RLC/Iub)
     ************************************************************************ */

    /* 
     * Create modules: down server -> down server tunnel
     */ 

    /* create server eth */
    result = ctp_mod_eth_rx_create(config->chain.sdu_pool, "DS Srv", config->server_if, &down_eth_server);
    ctp_config_chain_verify_step("Creating down server interface");

    /* create a thread only for down server */
    result = ctp_config_chain_create_module_thread(down_eth_server, SCHED_FIFO, 99, 0, &down_eth_server_thread);
    ctp_config_chain_verify_step("Creating thread for down server interface");

    /* create generator */
    result = ctp_mod_generator_create(&traffic_gen, "Traffic Gen", config->chain.sdu_pool);
    ctp_config_chain_verify_step("Creating traffic_gen");

    /* attach the traffic generator to eth rx thread */
    result = ctp_module_thread_attach_module(down_eth_server_thread, traffic_gen);
    ctp_config_chain_verify_step("Attaching traffic generator to traffic generator thread");

    /* create classifier -> iub encap */
    result = ctp_config_chain_ingress_rx_to_tunnel_tx(config, &down_server_classifier, &down_server_iub_encap, &down_server_scheduler, &control_gen);
    ctp_config_chain_verify_step("Creating ingress rx to tunnel tx chain");

    /* attach the control generator to traffic generator thread */
    result = ctp_module_thread_attach_module(down_eth_server_thread, control_gen);
    ctp_config_chain_verify_step("Attaching control generator to traffic generator thread");

    /* create a thread for the scheduler */
    result = ctp_config_chain_create_module_thread(down_server_scheduler, SCHED_FIFO, 99, 2, NULL);
    ctp_config_chain_verify_step("Creating thread for scheduler");

    /* create server tunnel */
    result = ctp_mod_eth_tx_create("DS Srv tnl", config->server_tunnel_if, &down_eth_tunnel_server);
    ctp_config_chain_verify_step("Creating down server tunnel interface");

    /* 
     * Create modules: down client tunnel -> down client
     */

    /* create client tunnel eth */
    result = ctp_mod_eth_rx_create(config->chain.sdu_pool, "DS Cln tnl", config->client_tunnel_if, &down_eth_tunnel_client);
    ctp_config_chain_verify_step("Creating down client tunnel interface");

    /* attach to the shared thread */
    result = ctp_module_thread_attach_module(shared_thread, down_eth_tunnel_client);
    ctp_config_chain_verify_step("Attaching down client to shared thread");

    /* create classifier -> ras */
    result = ctp_config_chain_tunnel_rx_to_egress_tx(config, &down_client_classifier, &down_client_rlc_ras);
    ctp_config_chain_verify_step("Creating tunnel rx to egress tx");

    /* create client eth */
    result = ctp_mod_eth_tx_create("DS Cln", config->client_if, &down_eth_client);
    ctp_config_chain_verify_step("Creating down client interface");

    /* 
     * Connect the modules: 
     */ 

    /* down server -> server classifier */
    result = ctp_module_set_output(down_eth_server, down_server_classifier);

    /* traffic generator -> server classifier */
    result = ctp_module_set_output(traffic_gen, down_server_classifier);

    /* down server iub encap -> down server tunnel eth */
    result = ctp_module_set_output(down_server_iub_encap, down_eth_tunnel_server);

    /* down client -> client classifier */
    result = ctp_module_set_output(down_eth_tunnel_client, down_client_classifier);

    /* down client rlc ras -> down client eth */
    result = ctp_module_set_output(down_client_rlc_ras, down_eth_client);

    /* set the unclassified output of the server classifier
     * to the server tunnel ethernet
     */
    result = ctp_mod_classifier_set_unclassified_output(down_server_classifier, down_eth_tunnel_server);

    /* set the unclassified output of the client tunnel classifier
     * to the client ethernet
     */
    result = ctp_mod_classifier_set_unclassified_output(down_client_classifier, down_eth_client);

    /* 
     * Create flows according to configuration
     */ 
    ctp_config_chain_init_generator_flows(traffic_gen, control_gen);

    /* 
     * Start the threads 
     */ 

    /* start threads from end to start */
    ctp_config_chain_start_module_thread(down_server_scheduler);
    ctp_config_chain_start_module_thread(down_eth_server);

    /* success */
    return RV_OK;

/* error */
err_chain:
    return result;
}

/* generate traffic into an rlc chain */
rv_t ctp_config_chain_downstream_rlc_iub_simulation(struct ctp_config *config)
{
    rv_t result;
    handle_t traffic_gen, traffic_generator_thread, analyzer, control_gen,
             down_server_classifier, down_server_iub_encap,
             down_client_classifier, down_client_rlc_ras,
             down_server_scheduler;

    /* 
     * Create modules
     */ 

    /* create generator */
    result = ctp_mod_generator_create(&traffic_gen, "Traffic Gen", config->chain.sdu_pool);
    ctp_config_chain_verify_step("Creating traffic_gen");

    /* create a thread for the traffic_gen */
    result = ctp_config_chain_create_module_thread(traffic_gen, SCHED_OTHER, 1, CTP_MODULE_THREAD_NO_AFFINITY, &traffic_generator_thread);
    ctp_config_chain_verify_step("Creating thread for traffic_generator");

    /* create classifier -> iub encap */
    result = ctp_config_chain_ingress_rx_to_tunnel_tx(config, &down_server_classifier, &down_server_iub_encap, &down_server_scheduler, &control_gen);
    ctp_config_chain_verify_step("Creating ingress rx to tunnel tx chain");

    /* attach the control generator to traffic generator thread */
    result = ctp_module_thread_attach_module(traffic_generator_thread, control_gen);
    ctp_config_chain_verify_step("Attaching control generator to traffic generator thread");

    /* create a thread for the scheduler */
    result = ctp_config_chain_create_module_thread(down_server_scheduler, SCHED_OTHER, 1, CTP_MODULE_THREAD_NO_AFFINITY, NULL);
    ctp_config_chain_verify_step("Creating thread for scheduler");

    /* create classifier -> ras */
    result = ctp_config_chain_tunnel_rx_to_egress_tx(config, &down_client_classifier, &down_client_rlc_ras);
    ctp_config_chain_verify_step("Creating tunnel rx to egress tx chain");

    /* create anaylzer module */
    result = ctp_mod_util_analyzer_create(&analyzer);
    ctp_config_chain_verify_step("Creating analyzer");
    
    /* 
     * Connect the modules
     */ 

    /* traffic_generator -> server classifier */
    ctp_module_set_output(traffic_gen, down_server_classifier);

    /* iub encap -> client classifier */
    ctp_module_set_output(down_server_iub_encap, down_client_classifier);

    /* client RLC reassembly -> analyzer */
    ctp_module_set_output(down_client_rlc_ras, analyzer);

    /* set the unclassified output of the server classifier
     * to the client classifier
     */
    ctp_mod_classifier_set_unclassified_output(down_server_classifier, down_client_classifier);

    /* set the unclassified output of the client classifier
     * to analyzer
     */
    ctp_mod_classifier_set_unclassified_output(down_client_classifier, analyzer);

    /* 
     * Create flows according to configuration
     */ 
    ctp_config_chain_init_generator_flows(traffic_gen, control_gen);

    /* create an unclassified flow */
    /* ctp_mod_generator_flow_create_ipv4_udp(traffic_gen, 
                                           "\x00\x01\x02\x04\x05\x06", 
                                           "\x00\x0a\x0b\x0c\x0d\x0e",
                                           inet_addr("100.100.100.100"), 0, 
                                           100, 200,   
                                           1000,      
                                           60,      
                                           1514); */

    /* 
     * Run the threads 
     */ 

    ctp_config_chain_start_module_thread(down_server_scheduler);
    ctp_config_chain_start_module_thread(traffic_gen);

    /* success */
    return RV_OK;

/* error */
err_chain:
    return result;
}

/* bridge downstream with thread for rx and thread for tx */
rv_t ctp_config_chain_downstream_bridge_to_tunnel(struct ctp_config *config, 
                                                  handle_t shared_thread)
{
    rv_t result;
    handle_t rx_thread, tx_thread, rx, tx, tx_queue;

    /* print */
    printf("Bridging %s to %s\n", config->server_if, config->server_tunnel_if);

    /* create receiver */
    result = ctp_mod_eth_rx_create(config->chain.sdu_pool, "ingress rx", config->server_if, &rx);
    ctp_config_chain_verify_step("Creating ingress rx");

    /* create transmitter */
    result = ctp_mod_eth_tx_create("tunnel tx", config->server_tunnel_if, &tx);
    ctp_config_chain_verify_step("Creating egress tx");

    /* set output of receiver to tx (will pass via queue) */
    ctp_module_set_output(rx, tx);

    /* create a thread for the receiver */
    ctp_module_thread_attach_module(shared_thread, rx);

    /* success */
    return RV_OK;

/* error */
err_chain:
    return result;
}

/* downstream scc */
rv_t ctp_config_chain_downstream_scc(struct ctp_config *config, handle_t shared_thread)
{
    rv_t result;
    handle_t eth_rx, eth_tx, scc, eth_rx_thread, scc_thread;

    /* create receiver */
    result = ctp_mod_eth_rx_create(config->chain.sdu_pool, "ingress rx", config->server_if, &eth_rx);
    ctp_config_chain_verify_step("Creating ingress rx");

    /* create a thread for the receiver */
    result = ctp_config_chain_create_module_thread(eth_rx, SCHED_FIFO, 99, 0, &eth_rx_thread);
    ctp_config_chain_verify_step("Creating thread for traffic_generator");

    /* create scc module */
    result = ctp_mod_scc_create("scc", &scc);
    ctp_config_chain_verify_step("Creating SCC");

    /* create a thread queue for the scc */
    result = ctp_config_chain_create_module_queue_thread(scc, SCHED_FIFO, 99, 1, &scc_thread);
    ctp_config_chain_verify_step("Creating thread for SCC");

    /* create transmitter */
    result = ctp_mod_eth_tx_create("tunnel tx", config->server_tunnel_if, &eth_tx);
    ctp_config_chain_verify_step("Creating egress tx");

    /* receiver sends to scc */
    ctp_module_set_output(eth_rx, scc);

    /* scc sends to tx */
    ctp_module_set_output(scc, eth_tx);

    /* 
     * Run the threads 
     */ 

    ctp_config_chain_start_module_queue_thread(scc_thread);
    ctp_config_chain_start_module_thread(eth_rx);

    /* success */
    return RV_OK;

/* error */
err_chain:
    return result;
}

/* downstream scc */
rv_t ctp_config_chain_downstream_scc_simulation(struct ctp_config *config, handle_t shared_thread)
{
    rv_t result;
    handle_t traffic_gen, eth_tx, scc, traffic_gen_thread, scc_thread;

    /* create generator */
    result = ctp_mod_generator_create(&traffic_gen, "Traffic Gen", config->chain.sdu_pool);
    ctp_config_chain_verify_step("Creating traffic gen");

    /* create a thread for the generator */
    result = ctp_config_chain_create_module_thread(traffic_gen, SCHED_OTHER, 1, CTP_MODULE_THREAD_NO_AFFINITY, &traffic_gen_thread);
    ctp_config_chain_verify_step("Creating thread for traffic_generator");

    /* create scc module */
    result = ctp_mod_scc_create("SCC", &scc);
    ctp_config_chain_verify_step("Creating SCC");

    /* create a thread queue for the scc */
    result = ctp_config_chain_create_module_queue_thread(scc, SCHED_OTHER, 1, CTP_MODULE_THREAD_NO_AFFINITY, &scc_thread);
    ctp_config_chain_verify_step("Creating thread for SCC");

    /* receiver sends to scc */
    ctp_module_set_output(traffic_gen, scc);

    /* 
     * Run the threads 
     */ 

    ctp_config_chain_start_module_queue_thread(scc);
    ctp_config_chain_start_module_thread(traffic_gen);

    /* success */
    return RV_OK;

/* error */
err_chain:
    return result;
}

/****************************************************************************** 
    Configuration interface
 *****************************************************************************/  

/* configuration init */
rv_t ctp_config_init()
{
    /* initialize configuration structure */
    bzero(&ctp_configuration, sizeof(struct ctp_config));

    /* set default modes */
    ctp_configuration.ds_mode = CTP_CFG_MODE_DISABLED;
    ctp_configuration.us_mode = CTP_CFG_MODE_DISABLED;

    /* initialize tunnel list */
    TAILQ_INIT(&ctp_configuration.nodeb_list);

    /* no description until initialized */
    ctp_configuration.descriptor_lines = 0;

    /* success */
    return RV_OK;
}

/* get user by id */
struct ctp_config_user* ctp_config_get_user_by_id(const user_id_t user_id)
{
    /* return user */
    return &ctp_configuration.user_db[user_id];
}

/* get user by index (order of creation) */ 
struct ctp_config_user* ctp_config_get_active_user_by_index(const unsigned int user_index)
{
    /* check */
    ctp_assert(user_index < array_size(ctp_config_active_users), "Invalid user index");

    /* return the active user @ index */
    return ctp_config_active_users[user_index];
}

/* get active number of nodebs */
unsigned int ctp_config_get_active_nodeb_count()
{
    /* return the count */
    return ctp_config_active_nodeb_count;
}

/* get active number of tunnels */
unsigned int ctp_config_get_active_tunnels_count()
{
    /* return the count */
    return ctp_config_active_tunnels_count;
}

/* get active number of users */
unsigned int ctp_config_get_active_users_count()
{
    /* return the count */
    return ctp_config_active_users_count;
}

/* initialize descriptor string */
void ctp_config_descriptor_string_init()
{
    struct ctp_config_nodeb *nodeb;
    struct ctp_config_tunnel *tunnel;
    struct ctp_config_user *user;
    char str_buffers[3][64];
    unsigned int descriptor_size;

    /* get total size */
    descriptor_size = ((ctp_config_get_active_users_count() +
                       (ctp_config_get_active_tunnels_count() * 2) +
                        ctp_config_get_active_nodeb_count()) * CTP_CONFIG_MAX_CONSOLE_WIDTH); 

    /* initialize it */
    memset(ctp_configuration.descriptor_string, 0, descriptor_size);

    /* iterate through nodebs */
    TAILQ_FOREACH(nodeb, &ctp_configuration.nodeb_list, config_entry)
    {
        /* print the nodeb */
        snprintf(ctp_configuration.descriptor_string[ctp_configuration.descriptor_lines], CTP_CONFIG_MAX_CONSOLE_WIDTH - 1,
                 "-- Node-B @ %s (max bandwidth: %dbps)\n", 
                 ip_addr_to_str(nodeb->ip_address, (char *)&str_buffers[0], sizeof(str_buffers[0])),
                 nodeb->max_bandwidth_bps);

        /* terminate line */
        ctp_configuration.descriptor_string[ctp_configuration.descriptor_lines][CTP_CONFIG_MAX_CONSOLE_WIDTH - 1] = '\0';

        /* next line */
        ctp_configuration.descriptor_lines++;

        /* iterate through tunnels */
        TAILQ_FOREACH(tunnel, &nodeb->tunnel_list, nodeb_entry)
        {
        	/* print the tunnel */
            snprintf(ctp_configuration.descriptor_string[ctp_configuration.descriptor_lines], CTP_CONFIG_MAX_CONSOLE_WIDTH - 1,
                     "tunnel[%d]: src-ip(%s) dscp(%d) users(%d)\n", 
                     tunnel->id,
                     ip_addr_to_str(ntohl(tunnel->ip_header.saddr), (char *)&str_buffers[0], sizeof(str_buffers[0])),
                     (tunnel->dscp & 0xFF),
                     tunnel->user_count);

            /* terminate line */
            ctp_configuration.descriptor_string[ctp_configuration.descriptor_lines][CTP_CONFIG_MAX_CONSOLE_WIDTH - 1] = '\0';

            /* increment line count */
            ctp_configuration.descriptor_lines++;

            /* print the tunnel */
            snprintf(ctp_configuration.descriptor_string[ctp_configuration.descriptor_lines], CTP_CONFIG_MAX_CONSOLE_WIDTH - 1,
                     "  L2: %s\n", 
                     tunnel->l2_desc_string);

            /* terminate line */
            ctp_configuration.descriptor_string[ctp_configuration.descriptor_lines][CTP_CONFIG_MAX_CONSOLE_WIDTH - 1] = '\0';

            /* increment line count */
            ctp_configuration.descriptor_lines++;

            /* iterate through users */
            TAILQ_FOREACH(user, &tunnel->user_list, tunnel_entry)
            {
                /* print the user. if you change this format, change ctp_get_config_desc_line_by_user_id as well */
                snprintf(ctp_configuration.descriptor_string[ctp_configuration.descriptor_lines], CTP_CONFIG_MAX_CONSOLE_WIDTH - 1,
                         "  user[%d] ip(%s) src-port(%d) dst-port(%d) fp(%s) rlc(%s) rlc-frag(%d) gen-control(%d, %d, %d) gen-traffic(%d, %d, %d)\n",
                         user->index,
                         ip_addr_to_str(user->ip_addr, (char *)&str_buffers[0], sizeof(str_buffers[0])),
                         htons(user->udp_header.source),
                         htons(user->udp_header.dest),
                         user->fp_header.format == CTP_CONFIG_FP_FORMAT_HS ? "hs" : "dch",
                         user->rlc_mode == CTP_CONFIG_RLC_MODE_UM ? "um" : "am",
                         user->frag_payload_size,
                         user->gen_control.rate, user->gen_control.min_size, user->gen_control.max_size,
                         user->gen_traffic.rate, user->gen_traffic.min_size, user->gen_traffic.max_size);

                /* terminate line */
                ctp_configuration.descriptor_string[ctp_configuration.descriptor_lines][CTP_CONFIG_MAX_CONSOLE_WIDTH - 1] = '\0';

                /* increment line count */
                ctp_configuration.descriptor_lines++;
            }
        }
    }
}

/* parse configuration file */
rv_t ctp_config_parse_file(const char *config_file)
{
    xmlDoc *doc = NULL;
    struct ctp_config_error err_info;
    rv_t result;

    /* init error line, incidating no error */
    err_info.line = -1;

    /*
     * this initialize the library and check potential ABI mismatches
     * between the version it was compiled for and the actual shared
     * library used.
     */
    LIBXML_TEST_VERSION

    /* copy config file location */
    safe_strncpy(ctp_configuration.config_file, 
                 config_file,
                 sizeof(ctp_configuration.config_file));

    /* parse the file and get the DOM */
    doc = xmlReadFile(config_file, NULL, 0);

    /* check success */
    if (doc == NULL)
    {
        /* bail */
        return RV_ERR_CANT_OPEN;
    }

    /* parse the configuration file */
    result = ctp_config_parse_doc_to_config(&ctp_configuration, 
                                            doc, 
                                            &err_info);

    /* check if ok */
    if (result != RV_OK)
    {
        /* print */
        printf("Configuration error [line %d]: %s\n", err_info.line, err_info.desc);
    }

    /* initiailize descriptor string */
    ctp_config_descriptor_string_init();

    /*free the document */
    xmlFreeDoc(doc);

    /*
     *Free the global variables that may
     *have been allocated by the parser.
     */
    xmlCleanupParser();

    /* result */
    return result;
}

/* execute configuration chain */
rv_t ctp_config_execute()
{
    handle_t shared_thread;
    rv_t result = RV_OK;

    /* space out */
    printf("\n\n");

    /* init the common chain stuff */
    ctp_config_init_chain(&ctp_configuration.chain);

    /* create the thread */
    ctp_assert(ctp_module_thread_create(SCHED_FIFO, 99, 4, &shared_thread) == RV_OK, 
               "Failed to create shared thread");

    /* create the appropriate chain */
    switch (ctp_configuration.ds_mode)
    {
        case CTP_CFG_MODE_RLC_IUB:              result = ctp_config_chain_downstream_rlc_iub(&ctp_configuration, shared_thread);             break;
        case CTP_CFG_MODE_RLC_IUB_SIMULATE:     result = ctp_config_chain_downstream_rlc_iub_simulation(&ctp_configuration);                 break;
        case CTP_CFG_MODE_BRIDGE:               result = ctp_config_chain_downstream_bridge_to_tunnel(&ctp_configuration, shared_thread);    break;
        case CTP_CFG_MODE_BRIDGE_VIA_TUNNEL:    result = ctp_config_chain_downstream_bridge_via_tunnel(&ctp_configuration, shared_thread);   break;
        case CTP_CFG_MODE_SCC:                  result = ctp_config_chain_downstream_scc(&ctp_configuration, shared_thread);                 break;
        case CTP_CFG_MODE_SCC_SIMULATE:         result = ctp_config_chain_downstream_scc_simulation(&ctp_configuration, shared_thread);      break;
        default: break;
    }

    /* verify success */
    ctp_assert(result == RV_OK, "Failed to create downstream chain");

    /* create the appropriate chain */
    switch (ctp_configuration.us_mode)
    {
        case CTP_CFG_MODE_BRIDGE:               result = ctp_config_chain_upstream_bridge(&ctp_configuration, shared_thread);              break;
        case CTP_CFG_MODE_BRIDGE_VIA_TUNNEL:    result = ctp_config_chain_upstream_bridge_via_tunnel(&ctp_configuration, shared_thread);   break;
        default: break;
    }

    /* verify success */
    ctp_assert(result == RV_OK, "Failed to create downstream chain");

    /* start the shared thread */
    ctp_assert(ctp_module_thread_start(shared_thread) == RV_OK, "Failed to start shared thread");

    /* success */
    return RV_OK;
}

/* get configuration */
const struct ctp_config* ctp_config_get()
{
    /* return the configuration */
    return &ctp_configuration;
}

/* add a nodeb to configuration */
void ctp_config_nodeb_add(struct ctp_config_nodeb *nodeb)
{
    /* add */
    TAILQ_INSERT_TAIL(&ctp_configuration.nodeb_list, nodeb, config_entry);
}

