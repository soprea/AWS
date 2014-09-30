#! /usr/bin/env python

import argparse
import os
import sys
from collections import defaultdict

import boto.ec2


def parse_args():
    parser = argparse.ArgumentParser(
        description='Display EC2 hosts in ssh-config or hosts file format',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('-k', '--aws-key', type=str,
        default=os.environ.get("AWS_ACCESS_KEY_ID"),
        help='Amazon EC2 Key, defaults to ENV[AWS_ACCESS_KEY_ID]')
    parser.add_argument('-s', '--aws-secret', type=str,
        default=os.environ.get("AWS_SECRET_ACCESS_KEY"),
        help='Amazon EC2 Secret, defaults to ENV[AWS_SECRET_ACCESS_KEY]')
    parser.add_argument('-r', '--region', type=str,
        default=os.environ.get("AWS_EC2_REGION"),
        help='Amazon EC2 Region, defaults to us-east-1 or ENV[AWS_EC2_REGION]')

    parser.add_argument('-t', '--tag', type=str,
        default='Name', dest='name_tag',
        help="Amazon EC2 Tag for instance name, defaults to 'Name'")

    parser.add_argument('--prefix', type=str, default='',
        help='prefix to the instance name')
    parser.add_argument('--ip_ltm', type=str, default='',
        help='ip to add to the ltm vip')
    parser.add_argument('--suffix', type=str, default='',
        help='suffix to the instance name')
    parser.add_argument('--domain', type=str, default='',
        help='domain to the instance name')

    parser.add_argument('--format', choices=['ssh', 'hosts', 'ltm_node', 'ltm_pool', 'ltm_vip'], default='ssh',
        help='output format. ssh-config or hosts or ltm_node or ltm_pool or ltm_vip file style. ')
    parser.add_argument('--filter', type=str, action='append', default=[],
        help=('Amazon EC2 API filter to limit the result returned. '
              '(Example: --filter instance-state-name=running)'))
    parser.add_argument('--use-elastic-ip', action='store_true',
        help='use elastic IP instead of private IP')

    return parser.parse_args()


def main(opts):
    aws_key = opts['aws_key']
    aws_secret = opts['aws_secret']
    region = opts['region']
    name_tag = opts['name_tag']
    prefix = opts['prefix']
    suffix = opts['suffix']
    domain = opts['domain']
    format = opts['format']
    filter = opts['filter']
    ip = opts['ip_ltm']
    use_elastic_ip = opts['use_elastic_ip']

    filters = dict([f.split('=', 1) for f in filter])
    if domain and not domain.startswith('.'):
        domain = '.' + domain

    ip_addr_attr = 'ip_address' if use_elastic_ip else 'private_ip_address'

    # validation
    if not aws_key or not aws_secret:
        if not aws_key:
            print >> sys.stderr,\
            "AWS_ACCESS_KEY_ID not set in environment and not",\
            "specified by -k AWS_KEY or --aws-key AWS_KEY"
        if not aws_secret:
            print >> sys.stderr,\
            "AWS_SECRET_ACCESS_KEY not set in envoronment and not",\
            "specified by -s AWS_SECRET or --aws-secret AWS_SECRET"
        sys.exit(2)

    region = region and boto.ec2.get_region(region,
        aws_access_key_id=aws_key,
        aws_secret_access_key=aws_secret)

    conn = boto.ec2.connection.EC2Connection(aws_key, aws_secret,
        region=region)

    # list of (instance_name, ip_address)
    instances = get_ec2_instances(conn, name_tag, ip_addr_attr, filters)

    # sort by name
    instances = sorted(instances)

    # print out
    if format == 'ssh':
       print_fn = print_ssh_config
    elif format == 'hosts':
       print_fn = print_hosts
    elif format == 'ltm_node':
       print_fn = print_ltm_node
    elif format == 'ltm_pool':
       print_fn = print_ltm_pool
    elif format == 'ltm_vip':
       print_fn = print_ltm_vip

    print_fn(instances, prefix, suffix, domain)

def get_ec2_instances(conn, name_tag, ip_addr_attr, filters):
    instances = []  # (instance_name, ip_address)
    reservations = conn.get_all_instances(filters=filters)
    for reservation in reservations:
        for instance in reservation.instances:
            instance_name = instance.tags.get(name_tag)
            ip_address = getattr(instance, ip_addr_attr)
            if instance_name and ip_address:
                pair = (instance_name, ip_address)
                instances.append(pair)
    return instances


def print_ssh_config(instances, prefix, suffix, domain):
    """ Print out as ssh-config file format """
    for instance_name, ip_address in instances:
        instance_name = prefix + instance_name + suffix + domain
        # double quote if name contains space
        instance_name = '"{0}"'.format(
            instance_name) if ' ' in instance_name else instance_name
        print "Host %s" % instance_name
        print "Hostname %s" % ip_address
        print ""

def print_hosts(instances, prefix, suffix, domain):
    """ Print out as hosts file format """
    for instance_name, ip_address in instances:
        if ' ' in instance_name:
            continue  # skip if name contains space.
        instance_name = prefix + instance_name + suffix + domain
        print "%s\t%s" % (ip_address, instance_name)

def print_ltm_node(instances, prefix, suffix, domain):
    """ Print out as ltm node file format in order to copy paste in F5 V.11"""
    print "================================================================================================================\n"
    for instance_name, ip_address in instances:
        if ' ' in instance_name:
            continue  # skip if name contains space.
        instance_name = prefix + instance_name + suffix + domain
        instance_name_l = instance_name.lower()
        #print "create ltm node %s {address %s description %s }" % (instance_name_l+'.mct.qa.cloud.synchronoss.net', ip_address, instance_name_l)
        print "create ltm node %s {address %s description %s }" % (instance_name_l, ip_address, instance_name_l)
    print "================================================================================================================\n"
    print "Watch after F5/NAT/ADM/BASTION node, maybe you don't need it.\nCheck the domain also. \n "

def print_ltm_pool(instances, prefix, suffix, domain):
    """ Print out as ltm node file format in order to copy paste in F5 V.11"""
    print "================================================================================================================\n"
    dict_data = dict()
    for instance_name, ip_address in instances:
        if ' ' in instance_name:
            continue  # skip if name contains space.
        instance_name_l = instance_name.lower()
        app = '-'+instance_name_l[:-3]+'-'
        instance_name_l = prefix + instance_name_l + suffix + domain
        pools = open('pools','r').read().split('\n')
        for pool in pools:
            app_port = pool[-4:]
            if app in pool:
                members = ' members add '+' { '+instance_name_l+':'+app_port+' { address '+ip_address+' } }'
                mem = 'create ltm pool '+pool+' { '+members[:-1]+' }'
                key = app
                dict_data.setdefault(key,' ')
                if key in dict_data[app]:
                    dict_data[app] = dict_data[app] + members
                else:
                    dict_data[app] = dict_data[app] + mem
    for value in dict_data.values():
        print value+' }'
    print "================================================================================================================\n"
    print "Watch after F5/NAT/ADM/BASTION node, maybe you don't need them.\nCheck the domain also. \n "

def print_ltm_vip(instances, prefix, suffix, domain):
    """ Print out as ltm vip file format in order to copy paste in F5 V.11"""
    print "================================================================================================================\n"
    dict2 = dict()
    pools = open('pools','r').read().split('\n')
    for pool in pools:
        app_port = pool[-4:]
        app1 = pool[4:]
        app2 = app1[:-10]
        app = app2
        print "create ltm virtual mct-%s-vip-%s {destination %s ip-protocol tcp mask 255.255.255.255 pool %s source 0.0.0.0/0 source-address-translation {type automap } profiles add {tcp{} http{}}}" % (app, prefix, prefix+':'+app_port, pool)


if __name__ == '__main__':
    args = vars(parse_args())
    main(args)
