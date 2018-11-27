#!/usr/bin/env python2
import argparse
import grpc
import os
import sys
from time import sleep
import json
import networkx
import itertools

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'utils/'))
import run_exercise
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

ROLE_LOAD_BALANCER = 0
ROLE_EXECUTION_UNIT = 1
ROLE_DATASTORE = 2

LOAD_BALANCER_SWITCH = 's0'
DATASTORE_SWITCH = 's99'

def printGrpcError(e):
    """
    Helper function to print a GRPC error

    :param e: the error object
    """

    print "gRPC Error:", e.details(),
    status_code = e.code()
    print "(%s)" % status_code.name,
    traceback = sys.exc_info()[2]
    print "[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno)

def load_topology(topo_file_path):
    """
    Helper function to load a topology

    :param topo_file_path: the path to the JSON file containing the topology
    """

    switch_number = 0
    switches = {}
    with open(topo_file_path) as topo_data:
        j = json.load(topo_data)
    json_hosts = j['hosts']
    json_switches = j['switches'].keys()
    json_links = run_exercise.parse_links(j['links'])
    mn_topo = run_exercise.ExerciseTopo(json_hosts, json_switches, json_links, "logs")
    for switch in mn_topo.switches():
        switch_number += 1
        bmv2_switch = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name=switch,
            address="127.0.0.1:%d" % (50050 + switch_number),
            device_id=(switch_number - 1),
            proto_dump_file="logs/%s-p4runtime-requests.txt" % switch)
        switches[switch] = bmv2_switch

    return (switches, mn_topo)

def main(p4info_file_path, bmv2_file_path, topo_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # Load the topology from the JSON file
        switches, mn_topo = load_topology(topo_file_path)

        # Establish a P4 Runtime connection to each switch
        for bmv2_switch in switches.values():
            bmv2_switch.MasterArbitrationUpdate()
            print "Established as controller for %s" % bmv2_switch.name

        # Load the P4 program onto each switch
        for bmv2_switch in switches.values():
            bmv2_switch.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                                    bmv2_json_file_path=bmv2_file_path)
            print "Installed P4 Program using SetForwardingPipelineConfig on %s" % bmv2_switch.name

        # Number of execution units is the total number of switches minus the load balancer and
        # datastore switches
        num_execution_units = len(switches) - 2
        num_hosts = len(mn_topo.hosts())
        execution_nodes = [switch for switch in switches if switches[switch].name not in [LOAD_BALANCER_SWITCH, DATASTORE_SWITCH]]
        # Assign roles to switches
        for switch in switches:
            switch_name = switches[switch].name
            role = ROLE_EXECUTION_UNIT
            if switch_name == LOAD_BALANCER_SWITCH:
                role = ROLE_LOAD_BALANCER
                for idx, execution_node in enumerate(execution_nodes):
                    # Add entries to load balance mapping
                    table_entry = p4info_helper.buildTableEntry(
                        table_name="MyIngress.load_balance_map",
                        match_fields={
                            "target_execution_node": idx
                        },
                        action_name="MyIngress.forward_to_execution_node",
                        action_params={
                            "port": mn_topo.port(switch, execution_node)[0],
                        }
                    )
                    switches[switch].WriteTableEntry(table_entry)
            elif switch_name == DATASTORE_SWITCH:
                role = ROLE_DATASTORE
            table_entry = p4info_helper.buildTableEntry(
                table_name="MyIngress.configuration",
                match_fields={
                },
                action_name="MyIngress.configure_switch",
                action_params={
                    "role": role,
                    "n_execution_units": num_execution_units,
                    "n_hosts": num_hosts,
                }
            )
            switches[switch].WriteTableEntry(table_entry)

    except KeyboardInterrupt:
        print " Shutting down."
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/switch.p4info')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/switch.json')
    parser.add_argument('--topo', help='Topology file',
                        type=str, action="store", required=False,
                        default='topology.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print "\np4info file not found: %s\nHave you run 'make'?" % args.p4info
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print "\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json
        parser.exit(1)
    if not os.path.exists(args.topo):
        parser.print_help()
        print "\nTopology file not found: %s" % args.topo
        parser.exit(1)
    main(args.p4info, args.bmv2_json, args.topo)
