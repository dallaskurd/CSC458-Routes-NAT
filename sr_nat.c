
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "sr_nat.h"
#include "sr_protocol.h"
#include "sr_router.h"
#include "sr_utils.h"

static const char internal_if[] = "eth1";

static void sr_nat_handle_ICMP(struct sr_instance* sr, sr_ip_hdr_t *ipPacket, unsigned int length,
                               struct sr_if *r_interface);
static void sr_nat_handle_TCP(struct sr_instance *sr, sr_ip_hdr_t *ipPacket, unsigned int length,
                              struct sr_if *r_interface);
static void sr_nat_handle_outbound(struct sr_instance *sr, sr_ip_hdr_t *packet, unsigned int length,
                                             struct sr_if *r_interface, sr_nat_mapping_t *natMapping);
static void sr_nat_handle_inbound(struct sr_instance *sr, sr_ip_hdr_t *packet, unsigned int length,
                                            struct sr_if *r_interface, sr_nat_mapping_t *natMapping);
static void sr_nat_recalculate_TCP_checksum(sr_ip_hdr_t *tcpPacket, unsigned int length);
static void sr_nat_destroy_connection(sr_nat_mapping_t *natMapping, sr_nat_connection_t *connection);
static void sr_nat_destroy_mapping(sr_nat_t *nat, sr_nat_mapping_t *natMapping);
static uint16_t sr_nat_create_mapping_number(sr_nat_t *nat, sr_nat_mapping_type mappingType);
static sr_nat_mapping_t *natTrustedLookupExternal(sr_nat_t *nat, uint16_t aux_ext,
                                                 sr_nat_mapping_type type);
static sr_nat_mapping_t *natTrustedLookupInternal(sr_nat_t *nat, uint32_t ip_int, uint16_t aux_int,
                                                 sr_nat_mapping_type type);
static sr_nat_mapping_t *natTrustedCreateMapping(sr_nat_t *nat, uint32_t ip_int, uint16_t aux_int,
                                                sr_nat_mapping_type type);
static sr_nat_connection_t *natTrustedFindConnection(sr_nat_mapping_t *natEntry, uint32_t ip_ext, 
                                                    uint16_t port_ext);


int sr_nat_init(struct sr_nat *nat) 
{ 

    /* Initializes the nat */
    assert(nat);

    /* Acquire mutex lock */
    pthread_mutexattr_init(&(nat->attr));
    pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

    /* Initialize timeout thread */
    pthread_attr_init(&(nat->thread_attr));
    pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

    /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */
    nat->mappings = NULL;
    nat->nextIcmpIdentNumber = STARTING_PORT_NUMBER;
    nat->nextTcpPortNumber = STARTING_PORT_NUMBER;

    return success;
}

int sr_nat_destroy(struct sr_nat *nat) 
{  

    /* Destroys the nat (free memory) */
    pthread_mutex_lock(&(nat->lock));

    while (nat->mappings)
    {
      sr_nat_destroy_mapping(nat, nat->mappings);
    }

    pthread_kill(nat->thread, SIGKILL);

    return pthread_mutex_destroy(&(nat->lock)) &&
           pthread_mutexattr_destroy(&(nat->attr));
}

void *sr_nat_timeout(void *nat_ptr) 
{  

    /* Periodic Timeout handling */
    struct sr_nat *nat = (struct sr_nat *)nat_ptr;

    while (1) 
    {
      sleep(1.0);
      pthread_mutex_lock(&(nat->lock));

      time_t curtime = time(NULL);
      sr_nat_mapping_t *mappingWalker = nat->mappings;

      while(mappingWalker)
      {

        /* If it is an ICMP packet */
        if (mappingWalker->type == nat_mapping_icmp)
        {
          if (difftime(curtime, mappingWalker->last_updated) > nat->icmpTimeout)
          {
            sr_nat_mapping_t *next = mappingWalker->next;

            /* Print out information of the destroyed mapping */
            sr_nat_destroy_mapping(nat, mappingWalker);
            mappingWalker = next;
          } else {
              mappingWalker = mappingWalker->next;
            }
        } else if (mappingWalker->type == nat_mapping_tcp) {

            /* If it is an TCP packet */
            sr_nat_connection_t *conn_walker = mappingWalker->conns;

            while(conn_walker)
            {
              if ((conn_walker->connectionState == nat_conn_connected)
                  && (difftime(curtime, conn_walker->lastAccessed)
                  > nat->tcpEstablishedTimeout))
              {
                sr_nat_connection_t *next = conn_walker->next;
                sr_nat_destroy_connection(mappingWalker, conn_walker);
                conn_walker = next;
              } else if (((conn_walker->connectionState == nat_conn_outbound_syn)
                         || (conn_walker->connectionState == nat_conn_time_wait))
                         && (difftime(curtime, conn_walker->lastAccessed)
                         > nat->tcpTransitoryTimeout))
                { 
                  sr_nat_connection_t *next = conn_walker->next;                  
                  sr_nat_destroy_connection(mappingWalker, conn_walker);
                  conn_walker = next;
                } else if ((conn_walker->connectionState == nat_conn_inbound_syn_pending)
                           && (difftime(curtime, conn_walker->lastAccessed)
                           > nat->tcpTransitoryTimeout))
                  { sr_nat_connection_t *next = conn_walker->next;

                    if (conn_walker->queuedInboundSyn) {
                      struct sr_rt *lpmatch = longest_prefix_matching(nat->routerState,
                                                                     ((conn_walker->queuedInboundSyn)->ip_src));
                      sr_icmp_with_payload(nat->routerState, conn_walker->queuedInboundSyn, lpmatch->interface, 3, 3);
                    }
                    sr_nat_destroy_connection(mappingWalker, conn_walker);
                    conn_walker = next;
                  } else {
                      conn_walker = conn_walker->next;
                    }
            }
            if (mappingWalker->conns == NULL) {
              sr_nat_mapping_t *next = mappingWalker->next;

              sr_nat_destroy_mapping(nat, mappingWalker);
              mappingWalker = next;
            } else {
                mappingWalker = mappingWalker->next;
              }
          } else {
              mappingWalker = mappingWalker->next;
            }
      }

      pthread_mutex_unlock(&(nat->lock));
    }

    return NULL;
}


/* Get the mapping associated with given external port
Must free the returned structure if it is not NULL */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat, uint16_t aux_ext,
                                             sr_nat_mapping_type type)
{
    pthread_mutex_lock(&(nat->lock));
   
    /* Handle lookup, malloc and assign to copy */
    sr_nat_mapping_t *copy = NULL;
    sr_nat_mapping_t *lookupResult = natTrustedLookupExternal(nat, aux_ext, type); 
   
    if (lookupResult != NULL)
    {
      lookupResult->last_updated = time(NULL);
      copy = malloc(sizeof(sr_nat_mapping_t));
      memcpy(copy, lookupResult, sizeof(sr_nat_mapping_t));
    }
   
    pthread_mutex_unlock(&(nat->lock));

    return copy;
}

/* Get the mapping associated with given internal (ip, port) pair
Must free the returned structure if it is not NULL */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
                                             uint32_t ip_int,
                                             uint16_t aux_int,
                                             sr_nat_mapping_type type)
{
    pthread_mutex_lock(&(nat->lock));

    /* Handle lookup, malloc and assign to copy */
    struct sr_nat_mapping *copy = NULL, *result = NULL;

    /* Search for mapping */

    for (sr_nat_mapping_t *mappingWalker = nat->mappings; mappingWalker != NULL; mappingWalker = mappingWalker->next)
    {
      if ((mappingWalker->type == type) && (mappingWalker->aux_int == aux_int) && (mappingWalker->ip_int == ip_int))
      {
        result = mappingWalker;
        break;
      }
    }

    if (result)
    {
      result->last_updated = time(NULL);
      copy = malloc(sizeof(struct sr_nat_mapping));
      assert(copy);
      memcpy(copy, result, sizeof(struct sr_nat_mapping));
    }

    pthread_mutex_unlock(&(nat->lock));

    return copy;
}

/* Insert a new mapping into the nat's mapping table
Actually returns a copy to the new mapping, for thread safety */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat, uint32_t ip_int, uint16_t aux_int,
                                            sr_nat_mapping_type type)
{
    pthread_mutex_lock(&(nat->lock));
   
    /* Handle insert here, create a mapping, and then return a copy of it */
    struct sr_nat_mapping *mapping = natTrustedCreateMapping(nat, ip_int, aux_int, type);
    struct sr_nat_mapping *copy = malloc(sizeof(sr_nat_mapping_t));
   
    if (type == nat_mapping_icmp)
    {
      printf("Created new ICMP mapping.\n");          
    }
    else if (type == nat_mapping_tcp)
    {
     printf("Created new TCP mapping.\n"); 
    }
   
    memcpy(copy, mapping, sizeof(sr_nat_mapping_t));

    printf("memcpy new ICMP mapping.\n"); 
    
    pthread_mutex_unlock(&(nat->lock));
    
    return copy;
}

void sr_nat_handle_ip_packet(struct sr_instance *sr,
                        sr_ip_hdr_t *ipPacket, unsigned int length,
                        struct sr_if *r_interface)
{
    if (ipPacket->ip_p == ip_protocol_tcp)
    {

      printf("** Received TCP\n");
      sr_nat_handle_TCP(sr, ipPacket, length, r_interface);
    } else if (ipPacket->ip_p == ip_protocol_icmp)
    {

      printf("** Received ICMP\n");
      sr_nat_handle_ICMP(sr, ipPacket, length, r_interface);
    } else {
        fprintf(stderr, "** Received packet of unknown IP protocol type %u. Dropping.\n", ipPacket->ip_p);
      }
}

void sr_nat_undo_mapping(struct sr_instance *sr, sr_ip_hdr_t *ip_hdr,
                         unsigned int length, struct sr_if *r_interface)
{
    sr_nat_mapping_t *natMap;
   
    if (sr_get_interface(sr, internal_if)->ip == r_interface->ip)
    {

      /* Undo an outbound conversion */
      if (ip_hdr->ip_p == ip_protocol_icmp)
      {
        sr_icmp_t0_hdr_t *icmpHeader = (sr_icmp_t0_hdr_t *) icmp_header(ip_hdr);
        natMap = sr_nat_lookup_external(sr->nat, icmpHeader->ident, nat_mapping_icmp);
        
        if (natMap != NULL)
        {
          icmpHeader->ident = natMap->aux_int;
          icmpHeader->icmp_sum = 0;
          icmpHeader->icmp_sum = cksum(icmpHeader, length - (ip_hdr->ip_hl)*4);
            
          ip_hdr->ip_src = natMap->ip_int;
          ip_hdr->ip_sum = 0;
          ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
        }
        free(natMap);
      }
      else if (ip_hdr->ip_p == ip_protocol_tcp)
      {
        sr_tcp_hdr_t *tcpHeader = tcp_header(ip_hdr);
        natMap = sr_nat_lookup_external(sr->nat, tcpHeader->sourcePort, nat_mapping_tcp);
         
        if (natMap != NULL)
        {
          tcpHeader->sourcePort = natMap->aux_int;
          ip_hdr->ip_src = natMap->ip_int;
            
          sr_nat_recalculate_TCP_checksum(ip_hdr, length);  
          ip_hdr->ip_sum = 0;
          ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
        }
        free(natMap);
      }
    } else {
        if (ip_hdr->ip_p == ip_protocol_icmp)
        {
          sr_icmp_t0_hdr_t *icmpHeader = (sr_icmp_t0_hdr_t *) icmp_header(ip_hdr);
          
          natMap = sr_nat_lookup_internal(sr->nat, ntohl(ip_hdr->ip_dst), 
                                         ntohs(icmpHeader->ident), nat_mapping_icmp);
          if (natMap != NULL)
          {
            icmpHeader->ident = htons(natMap->aux_ext);
            icmpHeader->icmp_sum = 0;
            icmpHeader->icmp_sum = cksum(icmpHeader, length - ip_hdr->ip_hl * 4);
            
            ip_hdr->ip_dst = sr_get_interface(sr, longest_prefix_matching(sr, ip_hdr->ip_src)->interface)->ip;
            ip_hdr->ip_sum = 0;
            ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
            
            free(natMap);
          }
        }
        else if (ip_hdr->ip_p == ip_protocol_tcp)
        {
          sr_tcp_hdr_t *tcpHeader = (sr_tcp_hdr_t *) tcp_header(ip_hdr);
          
          natMap = sr_nat_lookup_internal(sr->nat, ntohl(ip_hdr->ip_dst), 
                                         ntohs(tcpHeader->destinationPort), nat_mapping_icmp);
          if (natMap != NULL)
          {
            tcpHeader->destinationPort = htons(natMap->aux_ext);
            ip_hdr->ip_dst = sr_get_interface(sr, longest_prefix_matching(sr, ip_hdr->ip_src)->interface)->ip;
            
            sr_nat_recalculate_TCP_checksum(ip_hdr, length);
            ip_hdr->ip_sum = 0;
            ip_hdr->ip_sum = cksum(ip_hdr, (ip_hdr->ip_hl)*4);
            
            free(natMap);
          }
        }
      }
}

static void sr_nat_handle_ICMP(struct sr_instance *sr,
                               sr_ip_hdr_t *ipPacket, unsigned int length,
                               struct sr_if *r_interface)
{
    uint32_t ip_dst = ipPacket->ip_dst;
    sr_icmp_hdr_t *icmpHeader = icmp_header(ipPacket);

    /* if (!icmp_validpacket(ipPacket))
    {

      printf("** ICMP messed, dropping\n");
      return;
    } */

    if ((sr_get_interface(sr, internal_if)->ip == r_interface->ip)
        && (sr_packet_is_for_me(sr, ip_dst)))
    {

      /* Packet is for me and it's from inside */
      printf("** Outbound ICMP Packet for me\n");

      ip_handlepacketforme(sr, ipPacket, r_interface->name);
    }
    else if (sr_get_interface(sr, internal_if)->ip == r_interface->ip)
    {

      /* Outbound packet */
      printf("** Received Outbound ICMP Packet\n");

      if ((icmpHeader->icmp_type == type_echo_request)
         || (icmpHeader->icmp_type == type_echo_reply))
      { 

        printf("** Received Outbound ICMP Request/Reply\n");
        sr_icmp_t0_hdr_t *icmpPingHdr = (sr_icmp_t0_hdr_t *)icmpHeader;
        sr_nat_mapping_t *natLookupResult = sr_nat_lookup_internal(sr->nat, ipPacket->ip_src,
                                                                  icmpPingHdr->ident, nat_mapping_icmp);

        /* If mapping doesn't exist, create one */
        if (natLookupResult == NULL)
        {
          natLookupResult = sr_nat_insert_mapping(sr->nat, ipPacket->ip_src,
                                                 icmpPingHdr->ident, nat_mapping_icmp);
        }
        
        printf("** Mapping created for outbound ICMP ECHO\n");
        sr_nat_handle_outbound(sr, ipPacket, length, r_interface, natLookupResult);
        free(natLookupResult);
      } else {

          sr_ip_hdr_t *embeddedIpPacket = NULL;
          sr_nat_mapping_t *natLookupResult = NULL;

          if ((icmpHeader->icmp_type == type_dst_unreach)
             || (icmpHeader->icmp_type == type_time_exceeded))
          {

            printf("** Received Outbound ICMP Type 3\n");
            sr_icmp_t3_hdr_t *unreachableHeader = (sr_icmp_t3_hdr_t *)icmpHeader;
            embeddedIpPacket = (sr_ip_hdr_t *)unreachableHeader->data;
          }
          else
          {

            printf("** Received Outbound ICMP NOT KNOWN\n");
            return;
          }
          assert(embeddedIpPacket);

          if (embeddedIpPacket->ip_p == ip_protocol_icmp)
          {
            sr_icmp_t0_hdr_t *embeddedIcmpHeader = (sr_icmp_t0_hdr_t *) (icmp_header(embeddedIpPacket));
            if ((embeddedIcmpHeader->icmp_type == type_echo_request)
               || (embeddedIcmpHeader->icmp_type == type_echo_reply))
            {
              natLookupResult = sr_nat_lookup_internal(sr->nat, embeddedIpPacket->ip_dst,
                                                      embeddedIcmpHeader->ident, nat_mapping_icmp);
            }
            /* Otherwise, we will not have a mapping for this ICMP type. */
            /* Either way, echo request and echo reply are the only ICMP */
            /* packet types that can generate another ICMP packet. */ 
          }
          else if(embeddedIpPacket->ip_p == ip_protocol_tcp)
          {
            struct sr_tcp_hdr *embeddedTcpHeader = tcp_header(embeddedIpPacket);
            natLookupResult = sr_nat_lookup_internal(sr->nat, embeddedIpPacket->ip_dst,
                                                    embeddedTcpHeader->destinationPort, nat_mapping_tcp);
          } else {
              return;
            }

          /* If hit the entry for that packet, modify and send it out */
          if (natLookupResult != NULL)
          {
            sr_nat_handle_outbound(sr, ipPacket, length, r_interface, natLookupResult); 
            free(natLookupResult);
          }
        }
    } else {

        /* Inbound packet */
        printf("** Received Inbound ICMP Packet\n");

        if (!sr_packet_is_for_me(sr, ip_dst)) 
        {
          /* Packet no for me */
          printf("** Received Inbound ICMP Packet not for me\n");
          struct sr_rt* lpmatch = longest_prefix_matching(sr, ipPacket->ip_dst);

          if ((sr_get_interface(sr, internal_if)->ip)
             != (sr_get_interface(sr, lpmatch->interface)->ip))
          {
            ip_forwardpacket(sr, ipPacket, length, r_interface->name);
          } else {
              printf("** Unsolicited inbound ICMP packet received attempting to send to internal IP. Dropping.\n");
            }
          return;
        }
        else if (ip_dst == sr_get_interface(sr, internal_if)->ip)
        {
          /* For me but dst is internal interface */
          printf("** Received ICMP packet to our internal interface. Dropping.\n");
          return;
        }
        else if ((icmpHeader->icmp_type == type_echo_request)
                || (icmpHeader->icmp_type == type_echo_reply))   /* For me & is echo_request/reply */
        {
          sr_icmp_t0_hdr_t *icmp_ping_hdr = (sr_icmp_t0_hdr_t *)icmpHeader;
          sr_nat_mapping_t *natLookupResult = sr_nat_lookup_external(sr->nat, icmp_ping_hdr->ident,
                                                                    nat_mapping_icmp);

          if (natLookupResult == NULL)
          {
          
            /* No mapping exists. Assume ping is actually for us */
            ip_handlepacketforme(sr, ipPacket, r_interface->name);
          } else {
              sr_nat_handle_inbound(sr, ipPacket, length, r_interface,natLookupResult);
              free (natLookupResult);
            }
        } else {

            /* For me & is ICMP error message */
            sr_ip_hdr_t *embeddedIpPacket = NULL;
            sr_nat_mapping_t *natLookupResult = NULL;

            if ((icmpHeader->icmp_type == type_dst_unreach)
               || (icmpHeader->icmp_type ==type_time_exceeded))
            {
              sr_icmp_t3_hdr_t *unreachableHeader = (sr_icmp_t3_hdr_t *)icmpHeader;
              embeddedIpPacket = (sr_ip_hdr_t *)unreachableHeader->data;
            } else {
                return;
              }
            assert(embeddedIpPacket);

            if (embeddedIpPacket->ip_p == ip_protocol_icmp)
            {
              sr_icmp_t0_hdr_t *embeddedIcmpHeader = (sr_icmp_t0_hdr_t *)icmp_header(embeddedIpPacket);

              if ((embeddedIcmpHeader->icmp_type == type_echo_request)
                 || (embeddedIcmpHeader->icmp_type == type_echo_reply))
              {
                natLookupResult = sr_nat_lookup_external(sr->nat, embeddedIcmpHeader->ident, nat_mapping_icmp);
              }
            /* Otherwise, we will not have a mapping for this ICMP type
            Either way, echo request and echo reply are the only ICMP packet types that can generate another ICMP packet */
            }
            else if (embeddedIpPacket->ip_p == ip_protocol_tcp)
            {
              struct sr_tcp_hdr *embeddedTcpHeader = tcp_header(embeddedIpPacket);
              natLookupResult = sr_nat_lookup_external(sr->nat, embeddedTcpHeader->sourcePort, nat_mapping_tcp);
            } else {
                /* Unsupported protocol, drop the packet */
                return;
              }
            if (natLookupResult != NULL)
            {
              sr_nat_handle_inbound(sr, ipPacket, length, r_interface, natLookupResult);
              free(natLookupResult);
            }
          }
      }
}

static void sr_nat_handle_TCP(struct sr_instance *sr, sr_ip_hdr_t *ipPacket, unsigned int length,
                              struct sr_if *r_interface)
{

    sr_tcp_hdr_t *tcpHeader = tcp_header(ipPacket);
    uint8_t icmp_type;
    uint8_t icmp_code;

    /* Valid TCP packet  
    if (!tcp_validpacket(ipPacket))
    {

      printf("** TCP packet messed,dropping\n");
      return;
    } */ 
   
    if ((sr_get_interface(sr, internal_if)->ip == r_interface->ip)
       && (sr_packet_is_for_me(sr, ipPacket->ip_dst)))
    {

      printf("** Outbound TCP packet for me, sending port unreachable\n");

      ip_handlepacketforme(sr, ipPacket, r_interface->name);
    }
    else if (sr_get_interface(sr, internal_if)->ip == r_interface->ip)
    {

      sr_nat_mapping_t *natMapping = sr_nat_lookup_internal(sr->nat, ipPacket->ip_src,
                                                            tcpHeader->sourcePort, nat_mapping_tcp);
      
      if (ntohs(tcpHeader->offset_controlBits) & TCP_SYN_Mask)
      {
        printf("** Received Outbound TCP SYN packet\n");

        if (natMapping == NULL)
        {
	  
          /* Outbound SYN with no existed mapping, create new entry */
          printf("** Outbound TCP SYN with no mapping, create one\n");

          pthread_mutex_lock(&(sr->nat->lock));

          sr_nat_connection_t *firstConnection = malloc(sizeof(sr_nat_connection_t));
          sr_nat_mapping_t *sharedNatMapping;

          natMapping = malloc(sizeof(sr_nat_mapping_t));
          assert(firstConnection);
          assert(natMapping);
            
          sharedNatMapping = natTrustedCreateMapping(sr->nat, ipPacket->ip_src,
                                                    tcpHeader->sourcePort, nat_mapping_tcp);

          printf("** Trusted mapping created\n");
          assert(sharedNatMapping);
            
          /* Fill in first connection information */
          firstConnection->connectionState = nat_conn_outbound_syn;
          firstConnection->lastAccessed = time(NULL);
          firstConnection->queuedInboundSyn = NULL;
          firstConnection->external.ipAddress = ipPacket->ip_dst;
          firstConnection->external.portNumber = tcpHeader->destinationPort;
            
          /* Add to the list of connections */
          firstConnection->next = sharedNatMapping->conns;
          sharedNatMapping->conns = firstConnection;
            
          /* Create a copy so we can keep using it after we unlock the NAT table */
          memcpy(natMapping, sharedNatMapping, sizeof(sr_nat_mapping_t));

          printf("** Connection up?\n");  

          pthread_mutex_unlock(&(sr->nat->lock));

        } else {

            /* Outbound SYN with prior mapping. Add the connection if one doesn't exist */
            pthread_mutex_lock(&(sr->nat->lock));

            sr_nat_mapping_t *sharedNatMapping = natTrustedLookupInternal(sr->nat, ipPacket->ip_src,
                                                                       tcpHeader->sourcePort, nat_mapping_tcp);
            assert(sharedNatMapping);
            
            sr_nat_connection_t *connection = natTrustedFindConnection(sharedNatMapping,
                                                                      ipPacket->ip_dst, tcpHeader->destinationPort);  

            if (connection == NULL)
            {

              /* Connection does not exist. Create it */
              connection = malloc(sizeof(sr_nat_connection_t));
              assert(connection);
               
              /* Fill in connection information */
              connection->connectionState = nat_conn_outbound_syn;
              connection->external.ipAddress = ipPacket->ip_dst;
              connection->external.portNumber = tcpHeader->destinationPort;
               
              /* Add to the list of connections */
              connection->next = sharedNatMapping->conns;
              sharedNatMapping->conns = connection;
            }
            else if (connection->connectionState == nat_conn_time_wait)
            {

              /* Give client opportunity to reopen the connection */
              connection->connectionState = nat_conn_outbound_syn;
            }
            else if (connection->connectionState == nat_conn_inbound_syn_pending)
            {
              connection->connectionState = nat_conn_connected;
               
              if (connection->queuedInboundSyn) 
              {
                free(connection->queuedInboundSyn);
              }
            }

            pthread_mutex_unlock(&(sr->nat->lock));
          }
      }
      else if (natMapping == NULL)
      {
        /* Subsequent TCP packet without mapping  */
        return;
      }
      else if (ntohs(tcpHeader->offset_controlBits) & TCP_FIN_Mask)
      {
        /* Outbound FIN detected. Put connection into TIME_WAIT state */
        pthread_mutex_lock(&(sr->nat->lock));

        sr_nat_mapping_t *sharedNatMapping = natTrustedLookupInternal(sr->nat, ipPacket->ip_src,
                                                                   tcpHeader->sourcePort, nat_mapping_tcp);
        sr_nat_connection_t *associatedConnection = natTrustedFindConnection(sharedNatMapping, ipPacket->ip_dst,
                                                                            tcpHeader->destinationPort);
         
        if (associatedConnection)
        {
          associatedConnection->connectionState = nat_conn_time_wait;
        }
         
        pthread_mutex_unlock(&(sr->nat->lock));
      }
      
      /* Translate and forward */
      printf("** Translating and forwarding Outbound TCP\n");  

      sr_nat_handle_outbound(sr, ipPacket, length, r_interface, natMapping);

      printf("** Outbound TCP handled\n"); 

      if (natMapping) 
      { 
        free(natMapping);
      }

      printf("** NAT mapping freed after forwarding\n"); 

    } else {

      /* Inbound TCP packet */
      sr_nat_mapping_t *natMapping = sr_nat_lookup_external(sr->nat, tcpHeader->destinationPort,
                                                           nat_mapping_tcp);
      struct sr_rt* lpmatch = longest_prefix_matching(sr, ipPacket->ip_src);

      if (ntohs(tcpHeader->offset_controlBits) & TCP_SYN_Mask)
      {

        /* Inbound SYN received */
        if (natMapping == NULL)
        {
          /* Inbound TCP SYN without mapping, check destination port and send ICMP port unreachable denpending on it */
          if (tcpHeader->destinationPort >= 1024)
          {
            sleep(SIMULTANIOUS_OPEN_WAIT_TIME);
          }
          icmp_type = 3;
          icmp_code = 3;
          sr_icmp_with_payload(sr, ipPacket, lpmatch->interface, icmp_type, icmp_code);
            
          return;
        } else {

            /* Potential simultaneous open */
            pthread_mutex_lock(&(sr->nat->lock));
            
            sr_nat_mapping_t *sharedNatMapping = natTrustedLookupExternal(sr->nat, tcpHeader->destinationPort,
                                                                         nat_mapping_tcp);
            assert(sharedNatMapping);
            
            sr_nat_connection_t *connection = natTrustedFindConnection(sharedNatMapping, ipPacket->ip_src,
                                                                      tcpHeader->sourcePort);

            if (connection == NULL)
            {
              /* Potential simultaneous open */
              connection = malloc(sizeof(sr_nat_connection_t));
              assert(connection);
               
              /* Fill in connection information */
              connection->connectionState = nat_conn_inbound_syn_pending;
              connection->queuedInboundSyn = malloc(length);
              memcpy(connection->queuedInboundSyn, ipPacket, length);
              connection->external.ipAddress = ipPacket->ip_src;
              connection->external.portNumber = tcpHeader->sourcePort;
               
              /* Add to the list of connections */
              connection->next = sharedNatMapping->conns;
              sharedNatMapping->conns = connection;
              
              sr_nat_handle_inbound(sr, ipPacket, length, r_interface, natMapping);
      
              if (natMapping) 
              { 
                free(natMapping);
              }
              
              return;
            }
            else if (connection->connectionState == nat_conn_inbound_syn_pending)
            {
              return;
            }
            else if (connection->connectionState == nat_conn_outbound_syn)
            {
              connection->connectionState = nat_conn_connected;
            }
            
            pthread_mutex_unlock(&(sr->nat->lock));
          }
      }
      else if (natMapping == NULL)
      {

        /* TCP packet attempted to traverse the NAT on an unopened */
        icmp_type = 3;
        icmp_code = 3;
        sr_icmp_with_payload(sr, ipPacket, lpmatch->interface, icmp_type, icmp_code);
        
        return;
      }
      else if (ntohs(tcpHeader->offset_controlBits) & TCP_FIN_Mask)
      {

        /* Inbound FIN detected. Put connection into TIME_WAIT state */
        pthread_mutex_lock(&(sr->nat->lock));

        sr_nat_mapping_t *sharedNatMapping = natTrustedLookupExternal(sr->nat, tcpHeader->destinationPort,
                                                                   nat_mapping_tcp);
        sr_nat_connection_t *associatedConnection = natTrustedFindConnection(sharedNatMapping, ipPacket->ip_src,
                                                                            tcpHeader->sourcePort);         
        if (associatedConnection)
        {
          associatedConnection->connectionState = nat_conn_time_wait;
        }
         
        pthread_mutex_unlock(&(sr->nat->lock));
      } else {

          /* Lookup the associated connection */
          pthread_mutex_lock(&(sr->nat->lock));

          sr_nat_mapping_t *sharedNatMapping =  natTrustedLookupExternal(sr->nat, tcpHeader->destinationPort,
                                                                        nat_mapping_tcp);
          sr_nat_connection_t *associatedConnection = natTrustedFindConnection(sharedNatMapping, ipPacket->ip_src,
                                                                              tcpHeader->sourcePort);         
          if (associatedConnection == NULL)
          {

            /* Received unsolicited non-SYN packet when no active connection was found */
            pthread_mutex_unlock(&(sr->nat->lock));

            return;
          } else {
              pthread_mutex_unlock(&(sr->nat->lock));
            }
        }
      
      sr_nat_handle_inbound(sr, ipPacket, length, r_interface, natMapping);
      
      if (natMapping) 
      { 
        free(natMapping);
      }
    }
}

static void sr_nat_handle_outbound(struct sr_instance *sr, sr_ip_hdr_t *packet, unsigned int length,
                                             struct sr_if *r_interface, sr_nat_mapping_t *natMapping)
{

    if (packet->ip_p == ip_protocol_icmp)
    { 
      sr_icmp_hdr_t *icmpPacketHeader = icmp_header(packet);

      if ((icmpPacketHeader->icmp_type == type_echo_request)
         || (icmpPacketHeader->icmp_type == type_echo_reply))
      {
        printf("** Handle received outbound icmp echo\n");

        sr_icmp_t0_hdr_t *rewrittenIcmpHeader = (sr_icmp_t0_hdr_t *) icmpPacketHeader;

        int icmpLength = length - packet->ip_hl * 4;
        assert(natMapping);

        /* Handle ICMP identify remap and validate */
        rewrittenIcmpHeader->ident = natMapping->aux_ext;
        rewrittenIcmpHeader->icmp_sum = 0;
        rewrittenIcmpHeader->icmp_sum = cksum(rewrittenIcmpHeader, icmpLength);

        /* Handle IP address remap and validate */
        packet->ip_src = sr_get_interface(sr,longest_prefix_matching(sr, packet->ip_dst)->interface)->ip;

        ip_forwardpacket(sr, packet, length, r_interface->name);
      } else {

          printf("** Handle received outbound icmp type3\n");

          unsigned int icmpLength = length - packet->ip_hl * 4;
          sr_ip_hdr_t *originalDatagram;

          if (icmpPacketHeader->icmp_type == type_dst_unreach)
          {

            /* This packet is actually associated with a stream */
  	        sr_icmp_t3_hdr_t *unreachablePacketHeader = (sr_icmp_t3_hdr_t *) icmpPacketHeader;
  	        originalDatagram = (sr_ip_hdr_t*) (unreachablePacketHeader->data);
          }
  	      else if (icmpPacketHeader->icmp_type == type_time_exceeded)
  	      {
  	        sr_icmp_t3_hdr_t *unreachablePacketHeader = (sr_icmp_t3_hdr_t *) icmpPacketHeader;
  	        originalDatagram = (sr_ip_hdr_t *) (unreachablePacketHeader->data);
  	      }

  	      assert(natMapping);
  	  
        	if (originalDatagram->ip_p == ip_protocol_tcp)
        	{
        	  sr_tcp_hdr_t *originalTransportHeader = tcp_header(originalDatagram);
        	    
        	  /* Perform mapping on embedded payload */
        	  originalTransportHeader->destinationPort = natMapping->aux_ext;
        	  originalDatagram->ip_dst = sr_get_interface(sr, longest_prefix_matching(sr, packet->ip_dst)->interface)->ip;
        	}
        	else if (originalDatagram->ip_p == ip_protocol_icmp)
        	{
        	  sr_icmp_t0_hdr_t *originalTransportHeader = (sr_icmp_t0_hdr_t *) icmp_header(originalDatagram);
        	    
        	  /* Perform mapping on embedded payload */
        	  originalTransportHeader->ident = natMapping->aux_ext;
        	  originalDatagram->ip_dst = sr_get_interface(sr, longest_prefix_matching(sr, packet->ip_dst)->interface)->ip;
        	}
  	  
        	/* Update ICMP checksum */
        	icmpPacketHeader->icmp_sum = 0;
        	icmpPacketHeader->icmp_sum = cksum(icmpPacketHeader, icmpLength);
        	  
        	/* Rewrite actual packet header. */
        	packet->ip_src = sr_get_interface(sr, longest_prefix_matching(sr, packet->ip_dst)->interface)->ip;
        	ip_forwardpacket(sr, packet, length, r_interface->name);
        }
    }
    else if (packet->ip_p == ip_protocol_tcp)
    {

      printf("** Handle received outbound TCP\n");

      sr_tcp_hdr_t *tcpHeader = tcp_header(packet);

      printf("** TCP header loaded\n");

      tcpHeader->sourcePort = natMapping->aux_ext;
      packet->ip_src = sr_get_interface(sr, longest_prefix_matching(sr, packet->ip_dst)->interface)->ip;
      sr_nat_recalculate_TCP_checksum(packet, length);

      printf("** TCP header modified and checksum updated\n");

      ip_forwardpacket(sr, packet, length, r_interface->name);
    }
}

static void sr_nat_handle_inbound(struct sr_instance *sr, sr_ip_hdr_t *packet, unsigned int length,
                                            struct sr_if *r_interface, sr_nat_mapping_t *natMapping)
{
    if (packet->ip_p == ip_protocol_icmp)
    {
      sr_icmp_hdr_t *icmpPacketHeader =icmp_header(packet);
      
      if ((icmpPacketHeader->icmp_type == type_echo_request)
         || (icmpPacketHeader->icmp_type == type_echo_reply))
      {
        sr_icmp_t0_hdr_t *echoPacketHeader = (sr_icmp_t0_hdr_t *) icmpPacketHeader;
        int icmpLength = length - packet->ip_hl * 4;
       
        assert(natMapping);
         
        /* Handle ICMP identify remap and validate */
        echoPacketHeader->ident = natMapping->aux_int;
        echoPacketHeader->icmp_sum = 0;
        echoPacketHeader->icmp_sum = cksum(echoPacketHeader, icmpLength);
         
        /* Handle IP address remap and validate */
        packet->ip_dst = natMapping->ip_int;
         
        ip_forwardpacket(sr, packet, length, r_interface->name);
      }
      else 
      {
        int icmpLength = length - packet->ip_hl * 4;
        sr_ip_hdr_t *originalDatagram;

        if (icmpPacketHeader->icmp_type == type_dst_unreach)
        {
          /* This packet is actually associated with a stream */
          sr_icmp_t3_hdr_t *unreachablePacketHeader = (sr_icmp_t3_hdr_t *) icmpPacketHeader;
          originalDatagram = (sr_ip_hdr_t *) (unreachablePacketHeader->data);
        }
        else if (icmpPacketHeader->icmp_type == type_time_exceeded)
        {
          sr_icmp_t3_hdr_t *unreachablePacketHeader = (sr_icmp_t3_hdr_t *) icmpPacketHeader;
          originalDatagram = (sr_ip_hdr_t*) (unreachablePacketHeader->data);
        }
            
        assert(natMapping);
         
        if (originalDatagram->ip_p == ip_protocol_tcp)
        {
          sr_tcp_hdr_t *originalTransportHeader = tcp_header(originalDatagram);
            
          /* Perform mapping on embedded payload */
          originalTransportHeader->sourcePort = natMapping->aux_int;
          originalDatagram->ip_src = natMapping->ip_int;
        }
        else if (originalDatagram->ip_p == ip_protocol_icmp)
        {
          sr_icmp_t0_hdr_t *originalTransportHeader = (sr_icmp_t0_hdr_t *) icmp_header(originalDatagram);
            
          /* Perform mapping on embedded payload */
          originalTransportHeader->ident = natMapping->aux_int;
          originalDatagram->ip_src = natMapping->ip_int;
        }
         
        /* Update ICMP checksum */
        icmpPacketHeader->icmp_sum = 0;
        icmpPacketHeader->icmp_sum = cksum(icmpPacketHeader, icmpLength);
         
        /* Rewrite actual packet header */
        packet->ip_dst = natMapping->ip_int;
         
        ip_forwardpacket(sr, packet, length, r_interface->name);
      }
    }
    else if (packet->ip_p == ip_protocol_tcp)
    {
      sr_tcp_hdr_t *tcpHeader = tcp_header(packet);
            
      tcpHeader->destinationPort = natMapping->aux_int;
      packet->ip_dst = natMapping->ip_int;
      
      sr_nat_recalculate_TCP_checksum(packet, length);
      ip_forwardpacket(sr, packet, length, r_interface->name);
    }
}

static void sr_nat_recalculate_TCP_checksum(sr_ip_hdr_t *tcpPacket, unsigned int length)
{
    unsigned int tcpLength = length - tcpPacket->ip_hl * 4;
    uint8_t *packetCopy = malloc(sizeof(sr_tcp_ip_pseudo_hdr_t) + tcpLength);
    sr_tcp_ip_pseudo_hdr_t *checksummedHeader = (sr_tcp_ip_pseudo_hdr_t *) packetCopy;
    sr_tcp_hdr_t *tcpHeader = (sr_tcp_hdr_t *) (((uint8_t*) tcpPacket)
                              + tcpPacket->ip_len);
   
    memcpy(packetCopy + sizeof(sr_tcp_ip_pseudo_hdr_t), tcpHeader, tcpLength);

    checksummedHeader->sourceAddress = tcpPacket->ip_src;
    checksummedHeader->destinationAddress = tcpPacket->ip_dst;
    checksummedHeader->zeros = 0;
    checksummedHeader->protocol = ip_protocol_tcp;
    checksummedHeader->tcpLength = htons(tcpLength);
   
    tcpHeader->checksum = 0;
    tcpHeader->checksum = cksum(packetCopy, sizeof(sr_tcp_ip_pseudo_hdr_t) + tcpLength);
   
    free(packetCopy);
}

static void sr_nat_destroy_connection(sr_nat_mapping_t *natMapping, sr_nat_connection_t *connection)
{

    sr_nat_connection_t *req, *prev = NULL, *next = NULL;
   
    if (natMapping && connection)
    {
      for (req = natMapping->conns; req != NULL; req = req->next)
      {
        if (req == connection)
        {
          if (prev)
          {
            next = req->next;
            prev->next = next;
          } else {
              next = req->next;
              natMapping->conns = next;
            }
            
          break;
        }
        prev = req;
      }
      
      if(connection->queuedInboundSyn)
      {
        free(connection->queuedInboundSyn);
      }
      
      free(connection);
    }
}

static void sr_nat_destroy_mapping(sr_nat_t *nat, sr_nat_mapping_t *natMapping)
{
    if (natMapping)
    {
      sr_nat_mapping_t *req, *prev = NULL, *next = NULL;

      /* Search the link list, destroy and link prev/next */
      for (req = nat->mappings; req != NULL; req = req->next)
      {
        if (req == natMapping)
        {
          if (prev)
          {
            next = req->next;
            prev->next = next;
          } else {
              next = req->next;
              nat->mappings = next;
            }

          break;
        }
        prev = req;
      }

      while (natMapping->conns != NULL)
      {
        sr_nat_connection_t *curr = natMapping->conns;
        natMapping->conns = curr->next;

        free(curr);
      }

      free(natMapping);
    }
}

static uint16_t sr_nat_create_mapping_number(sr_nat_t *nat, sr_nat_mapping_type mappingType)
{
    uint16_t startIndex;
    sr_nat_mapping_t *mapping_walker = nat->mappings;

    if (mappingType == nat_mapping_icmp)
    {
      startIndex = nat->nextIcmpIdentNumber;
    }
    else if (mappingType == nat_mapping_tcp)
    {
      startIndex = nat->nextTcpPortNumber;
    }

    /* Look to see if a mapping already exists for this port number */
    while (mapping_walker)
    {
      if ((mapping_walker->type == mappingType)
         && (htons(startIndex) == mapping_walker->aux_ext))
      {
        
        /* Mapping already exists for this value. Go to the next one and start the search over. */
        startIndex = (startIndex == LAST_PORT_NUMBER) ? STARTING_PORT_NUMBER : (startIndex + 1);
        mapping_walker = nat->mappings;
      } else {
          mapping_walker = mapping_walker->next;
        }
    }

    /* Setup the next search start location for the next mapping */
    if (mappingType == nat_mapping_icmp)
    {
      nat->nextIcmpIdentNumber = (startIndex == LAST_PORT_NUMBER) ? STARTING_PORT_NUMBER : (startIndex + 1);
    }
    else if (mappingType == nat_mapping_tcp)
    {
      nat->nextTcpPortNumber = (startIndex == LAST_PORT_NUMBER) ? STARTING_PORT_NUMBER : (startIndex + 1);
    }

    return startIndex;
}

static sr_nat_mapping_t *natTrustedLookupExternal(sr_nat_t *nat, uint16_t aux_ext,
                                                 sr_nat_mapping_type type)
{
    for (sr_nat_mapping_t * mappingWalker = nat->mappings; mappingWalker != NULL ; mappingWalker =
      mappingWalker->next)
    {
      if ((mappingWalker->type == type) && (mappingWalker->aux_ext == aux_ext))
      {
         return mappingWalker;
      }
    }

    return NULL;
}

static sr_nat_mapping_t *natTrustedLookupInternal(sr_nat_t *nat, uint32_t ip_int, uint16_t aux_int,
                                                 sr_nat_mapping_type type)
{
    sr_nat_mapping_t *mappingWalker;
      
    for (mappingWalker = nat->mappings; mappingWalker != NULL; mappingWalker = mappingWalker->next)
    {
      if ((mappingWalker->type == type) && (mappingWalker->ip_int == ip_int)
         && (mappingWalker->aux_int == aux_int))
      {
         return mappingWalker;
      }
    }

    return NULL;
}

static sr_nat_mapping_t *natTrustedCreateMapping(sr_nat_t *nat, uint32_t ip_int, uint16_t aux_int,
                                                sr_nat_mapping_type type)
{
    struct sr_nat_mapping *mapping = malloc(sizeof(sr_nat_mapping_t));
   
    mapping->aux_ext = htons(sr_nat_create_mapping_number(nat, type));
    mapping->conns = NULL;
   
    /* Store mapping information */
    mapping->aux_int = aux_int;
    mapping->ip_int = ip_int;
    mapping->last_updated = time(NULL);
    mapping->type = type;
   
    /* Add mapping to the front of the list. */
    mapping->next = nat->mappings;
    nat->mappings = mapping;
   
    return mapping;
}

static sr_nat_connection_t *natTrustedFindConnection(sr_nat_mapping_t *natEntry, uint32_t ip_ext, 
                                                    uint16_t port_ext)
{
    sr_nat_connection_t *conn_walker = natEntry->conns;
   
    while (conn_walker != NULL)
    {
      if ((conn_walker->external.ipAddress == ip_ext) 
         && (conn_walker->external.portNumber == port_ext))
      {
         conn_walker->lastAccessed = time(NULL);
         break;
      }
      
      conn_walker = conn_walker->next;
    }
   
    return conn_walker;
}
