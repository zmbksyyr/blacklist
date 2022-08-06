# -*- coding: utf-8 -*-

import time
import requests
import re

gfw_url = 'https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/gfw.txt'
greatfire_url = 'https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/greatfire.txt'
telegram_url = 'https://core.telegram.org/resources/cidr.txt'

def get_rule(rules_url):
    success = False
    try_times = 0
    r = None
    while try_times < 5 and not success:
        r = requests.get(rules_url)
        if r.status_code != 200:
            time.sleep(1)
            try_times = try_times + 1
        else:
            success = True
            break

    if not success:
        raise Exception('error in request %s\n\treturn code: %d' % (rules_url, r.status_code) )

    return r.text


def clear_format(rule):
    rules = []

    rule = rule.split('\n')
    for row in rule:
        row = row.strip()
        rules.append(row)

    return rules

def getRulesStringFromFile(allrules, kind):
    ret = ''
    for rule in allrules:
        rule = rule.strip('\r\n')
        if not len(rule):
            continue

        if rule.startswith('#'):
            ret += rule + '\n'
        else:
            prefix = 'DOMAIN-SUFFIX'
            if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', rule) or re.match(r'^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$'):
                prefix = 'IP-CIDR'
                if '/' not in rule:
                    rule += '/32'
            elif '.' not in rule and len(rule) > 1:
                prefix = 'DOMAIN-KEYWORD'

            ret += prefix + ',%s,%s\n' % (rule, kind)

    return ret

# main

rule = get_rule(gfw_url) + get_rule(greatfire_url) + get_rule(telegram_url)

rules = clear_format(rule)

rules = list( set(rules) )

# make values
values = {}

values['build_time'] = time.strftime("%Y-%m-%d %H:%M:%S")

values['gfwlist'] = getRulesStringFromFile(rules, 'Proxy')

# make confs
file_template = open('blacklist.template', 'r', encoding='utf-8')
template = file_template.read()

file_output = open('blacklist.conf', 'w', encoding='utf-8')

marks = re.findall(r'{{(.+)}}', template)

for mark in marks:
	template = template.replace('{{'+mark+'}}', values[mark])

file_output.write(template)
