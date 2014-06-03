cmake_minimum_required(VERSION 2.0)

# declare project
project(ctp)

# set include directories
include_directories("${CMAKE_SOURCE_DIR}" "${CMAKE_SOURCE_DIR}/../us1.0")

# set link directories
link_directories("${CMAKE_SOURCE_DIR}/../us1.0/Env/PC-Linux/Out/Debug")

# compiler options 
# -DCTP_INJECT_ERROR_RATE=100: inject random errors into packets/transport 
# -DCTP_INJECT_LOSS_RATE=100: inject random losses
# -DCTP_OUTPUT_IUB_TO_PCAP: dump all packets outgoing to the tunnel to a pcap file
# -DCTP_EVENT_LOGS_ENABLED: perform real-time logging to memory
# -DCTP_SIMULATION: Perform any operations that will allow to run on non-CTP hardware
#
add_definitions(`xml2-config --cflags` -D_GNU_SOURCE -DCTP_SIMULATION)

# create ctp executable
add_executable(ctp 
                common/utils/common.c 
                common/loggers/rx/ctp_log_rx.c 
                common/loggers/event/ctp_log_event.c 
                common/buffer/bufq/ctp_bufq.c 
                common/buffer/bufpool/ctp_bufpool.c 
                config/ctp_config.c 
                config/ctp_config_user.c 
                config/ctp_config_nodeb.c 
                modules/base/ctp_module.c 
                modules/base/ctp_module_msgpool.c 
                modules/base/ctp_module_queue.c 
                modules/base/ctp_module_thread.c 
                modules/eth/ctp_mod_eth.c
                modules/eth/ctp_mod_eth_rx.c 
                modules/eth/ctp_mod_eth_tx.c 
                modules/classifier/ctp_mod_classifier.c 
                modules/rlc/ctp_mod_rlc_seg.c 
                modules/rlc/ctp_mod_rlc_ras.c 
                modules/generator/ctp_mod_generator.c 
                modules/generator/ctp_mod_generator_flow.c 
                modules/util/ctp_mod_util_analyzer.c 
                modules/iub/ctp_mod_iub_encap.c 
                modules/iub/ctp_mod_iub_decap.c 
                modules/scheduler/ctp_mod_scheduler.c 
                modules/scc/ctp_mod_scc.c 
                ctp.c)

# add libraries to link to
target_link_libraries (ctp pthread z xml2 pfring rt scc)
