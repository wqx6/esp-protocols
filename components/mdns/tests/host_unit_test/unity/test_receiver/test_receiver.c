/*
 * SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */

#include "unity.h"
#include "create_test_packet.h"
#include "unity_main.h"
#include "mock_mdns_pcb.h"
#include "mock_mdns_send.h"
#include "mdns_private.h"
#include "mdns_browser.h"
#include "mdns_querier.h"

static void test_mdns_hostname_queries(void)
{
    // Define the queries for test4.local and test.local
    mdns_test_query_t queries[] = {
        { "test4.local", 1, 1 },  // A record for test4.local
        { "test.local", 1, 1 }    // A record for test.local
    };

    // Create and send the packet
    size_t packet_len;
    uint8_t* packet = create_mdns_test_packet(
                          queries, 2,    // Queries
                          NULL, 0,       // No answers
                          NULL, 0,       // No additional records
                          &packet_len
                      );

    send_test_packet_multiple(packet, packet_len);
}

// Example of a more complex test with answers and additional records
static void test_mdns_with_answers(void)
{
    // Define a query for _http._tcp.local PTR record
    mdns_test_query_t queries[] = {
        { "_http._tcp.local", 12, 1 }  // PTR record
    };

    // Example data for a PTR record (simplified)
    uint8_t ptr_data[200];
    size_t ptr_data_len = encode_dns_name(ptr_data, "test._http._tcp.local");

    // Define an answer for the PTR record
    mdns_test_answer_t answers[] = {
        { "_http._tcp.local", 12, 1, 120, ptr_data_len, ptr_data }
    };

    // Create and send the packet
    size_t packet_len;
    uint8_t* packet = create_mdns_test_packet(
                          queries, 1,    // Single query
                          answers, 1,    // Single answer
                          NULL, 0,       // No additional records
                          &packet_len
                      );

    send_test_packet_multiple(packet, packet_len);

}

/*
 * Regression test for fa84ee6: packets shorter than MDNS_HEAD_LEN (12) must
 * be rejected before reading the additional RR count at offset 10.
 * An 11-byte AFL input (id_000005) previously passed the old check and read
 * one byte past the RX buffer.
 */
static void test_mdns_reject_short_packet(void)
{
    static const uint8_t eleven_byte_packet[] = {
        0x00, 0xc0, 0x32, 0x00, 0x01, 0x00, 0x14, 0x00, 0x00, 0x54, 0x01
    };

    for (size_t len = 0; len < MDNS_HEAD_LEN; len++) {
        const uint8_t *data = eleven_byte_packet;
        send_packet(true, true, (uint8_t *)data, len);
        send_packet(true, false, (uint8_t *)data, len);
        send_packet(false, true, (uint8_t *)data, len);
        send_packet(false, false, (uint8_t *)data, len);
    }
}

static void test_query_ptr_result_keeps_multiple_subtypes(void)
{
    mdns_search_once_t search = { 0 };
    search.max_results = 1;

    mdns_result_t *result = mdns_priv_query_result_add_ptr(&search, "printer", "_ipp", "_tcp", "_color",
                                                           0, MDNS_IP_PROTOCOL_V4, 120);
    mdns_priv_query_result_add_ptr(&search, "printer", "_ipp", "_tcp", "_duplex",
                                   0, MDNS_IP_PROTOCOL_V4, 120);
    mdns_priv_query_result_add_ptr(&search, "printer", "_ipp", "_tcp", "_color",
                                   0, MDNS_IP_PROTOCOL_V4, 120);

    TEST_ASSERT_NOT_NULL(result);
    TEST_ASSERT_EQUAL_UINT32(2, result->subtype_count);
    TEST_ASSERT_EQUAL_STRING("_color", result->subtypes[0].subtype);
    TEST_ASSERT_EQUAL_STRING("_duplex", result->subtypes[1].subtype);
    mdns_priv_query_results_free(search.result);
}

static bool result_has_subtype(const mdns_result_t *result, const char *subtype)
{
    for (size_t i = 0; i < result->subtype_count; i++) {
        if (strcmp(result->subtypes[i].subtype, subtype) == 0) {
            return true;
        }
    }
    return false;
}

static void test_query_subtype_goodbye_removes_subtype(void)
{
    mdns_search_once_t search = { 0 };
    search.max_results = 1;

    mdns_result_t *result = mdns_priv_query_result_add_ptr(&search, "printer", "_ipp", "_tcp", "_color",
                                                           0, MDNS_IP_PROTOCOL_V4, 120);
    mdns_priv_query_result_add_ptr(&search, "printer", "_ipp", "_tcp", "_duplex",
                                   0, MDNS_IP_PROTOCOL_V4, 120);
    mdns_priv_query_result_add_ptr(&search, "printer", "_ipp", "_tcp", "_color",
                                   0, MDNS_IP_PROTOCOL_V4, 0);

    TEST_ASSERT_NOT_NULL(result);
    TEST_ASSERT_EQUAL_UINT32(120, result->ttl);
    TEST_ASSERT_EQUAL_UINT32(1, result->subtype_count);
    TEST_ASSERT_EQUAL_STRING("_duplex", result->subtypes[0].subtype);
    mdns_priv_query_results_free(search.result);
}

static void test_browse_subtype_goodbye_keeps_service_result(void)
{
    mdns_browse_t browse = { 0 };
    mdns_browse_sync_t *sync = mdns_priv_browse_ensure_sync(&browse, NULL);
    TEST_ASSERT_NOT_NULL(sync);

    mdns_priv_browse_result_add_ptr(&browse, "printer", "_ipp", "_tcp", NULL,
                                    0, MDNS_IP_PROTOCOL_V4, 120, sync);
    mdns_priv_browse_result_add_ptr(&browse, "printer", "_ipp", "_tcp", "_color",
                                    0, MDNS_IP_PROTOCOL_V4, 120, sync);
    mdns_priv_browse_sync_free(sync);

    sync = mdns_priv_browse_ensure_sync(&browse, NULL);
    TEST_ASSERT_NOT_NULL(sync);
    mdns_priv_browse_result_add_ptr(&browse, "printer", "_ipp", "_tcp", "_color",
                                    0, MDNS_IP_PROTOCOL_V4, 0, sync);

    TEST_ASSERT_NOT_NULL(browse.result);
    TEST_ASSERT_EQUAL_UINT32(120, browse.result->ttl);
    TEST_ASSERT_EQUAL_UINT32(0, browse.result->subtype_count);
    TEST_ASSERT_EQUAL_PTR(browse.result, sync->sync_result->result);
    mdns_priv_browse_sync_free(sync);
    mdns_priv_query_results_free(browse.result);
}

static void test_service_lookups_include_multiple_subtypes(void)
{
    mdns_result_t *result = NULL;

    TEST_ASSERT_EQUAL(ESP_OK, mdns_service_add("self-lookup", "_lookup", "_tcp", 80, NULL, 0));
    TEST_ASSERT_EQUAL(ESP_OK, mdns_service_subtype_add_for_host("self-lookup", "_lookup", "_tcp", "test",
                                                                "_self-one"));
    TEST_ASSERT_EQUAL(ESP_OK, mdns_service_subtype_add_for_host("self-lookup", "_lookup", "_tcp", "test",
                                                                "_self-two"));
    TEST_ASSERT_EQUAL(ESP_OK, mdns_lookup_selfhosted_service("self-lookup", "_lookup", "_tcp", 1, &result));
    TEST_ASSERT_NOT_NULL(result);
    TEST_ASSERT_EQUAL_UINT32(2, result->subtype_count);
    TEST_ASSERT_TRUE(result_has_subtype(result, "_self-one"));
    TEST_ASSERT_TRUE(result_has_subtype(result, "_self-two"));
    mdns_query_results_free(result);

    result = NULL;
    TEST_ASSERT_EQUAL(ESP_OK, mdns_service_add_for_host("delegated-lookup", "_lookup", "_tcp", "test4", 80,
                                                        NULL, 0));
    TEST_ASSERT_EQUAL(ESP_OK, mdns_service_subtype_add_for_host("delegated-lookup", "_lookup", "_tcp", "test4",
                                                                "_delegated-one"));
    TEST_ASSERT_EQUAL(ESP_OK, mdns_service_subtype_add_for_host("delegated-lookup", "_lookup", "_tcp", "test4",
                                                                "_delegated-two"));
    TEST_ASSERT_EQUAL(ESP_OK, mdns_lookup_delegated_service("delegated-lookup", "_lookup", "_tcp", 1, &result));
    TEST_ASSERT_NOT_NULL(result);
    TEST_ASSERT_EQUAL_UINT32(2, result->subtype_count);
    TEST_ASSERT_TRUE(result_has_subtype(result, "_delegated-one"));
    TEST_ASSERT_TRUE(result_has_subtype(result, "_delegated-two"));
    mdns_query_results_free(result);
}

static void mdns_priv_create_answer_from_parsed_packet_Callback(mdns_parsed_packet_t* parsed_packet, int cmock_num_calls)
{
    printf("callback\n");
}

void setup_cmock(void)
{
    mdns_priv_probe_all_pcbs_CMockIgnore();
    mdns_priv_pcb_announce_CMockIgnore();
    mdns_priv_pcb_send_bye_service_CMockIgnore();
    mdns_priv_pcb_check_probing_services_CMockIgnore();
    mdns_priv_pcb_is_after_probing_IgnoreAndReturn(true);

    mdns_priv_clear_tx_queue_CMockIgnore();
    mdns_priv_remove_scheduled_service_packets_CMockIgnore();
    mdns_priv_create_answer_from_parsed_packet_Stub(mdns_priv_create_answer_from_parsed_packet_Callback);
}

void run_unity_tests(void)
{
    UNITY_BEGIN();

    // Run hostname queries test
    RUN_TEST(test_mdns_hostname_queries);

    // Run test with answers
    RUN_TEST(test_mdns_with_answers);

    RUN_TEST(test_mdns_reject_short_packet);

    RUN_TEST(test_query_ptr_result_keeps_multiple_subtypes);

    RUN_TEST(test_query_subtype_goodbye_removes_subtype);

    RUN_TEST(test_browse_subtype_goodbye_keeps_service_result);

    RUN_TEST(test_service_lookups_include_multiple_subtypes);

    UNITY_END();
}
