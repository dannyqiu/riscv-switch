NO_P4 = true
BMV2 = simple_switch_grpc
P4C_ARGS = --p4runtime-file $(basename $@).p4info --p4runtime-format text
BUILD_DIR = build
PCAP_DIR = pcaps
LOG_DIR = logs
TOPO = topology.json
P4C = p4c-bm2-ss
RUN_SCRIPT = utils/run_exercise.py

source := switch.p4
outfile := $(source:.p4=.json)
compiled_json := $(BUILD_DIR)/$(outfile)

all: build run

run:
	sudo python $(RUN_SCRIPT) -t $(TOPO) -j $(compiled_json) -b $(BMV2)

stop:
	sudo mn -c

build: dirs $(compiled_json)

$(BUILD_DIR)/%.json: %.p4
	$(P4C) --p4v 16 $(P4C_ARGS) -o $@ $<

dirs:
	mkdir -p $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR)

clean: stop
	rm -f *.pcap
	rm -rf $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR)
