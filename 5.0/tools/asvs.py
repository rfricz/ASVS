#!/usr/bin/env python
# -*- coding: utf-8 -*-
''' ASVS document parser and converter class.

    Based upon code written for MASVS By Bernhard Mueller
    Significant improvement by Jonny Schnittger @JonnySchnittger
    Additional modifications by Josh Grossman @tghosth
    Copyright (c) 2023 OWASP Foundation

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

    '''

import os
import re
import json
import base64
import urllib.request
import datetime
from xml.sax.saxutils import escape
import csv
from dicttoxml2 import dicttoxml
import xml.etree.ElementTree as ET
import copy
from marko.ext.gfm import gfm

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO


class ASVS:
    asvs = {}
    asvs['Name'] = "Application Security Verification Standard Project"
    asvs['ShortName'] = "ASVS"
    asvs['Version'] = ""
    asvs['Description'] = ("The OWASP Application Security Verification Standard (ASVS) Project "
            "provides a basis for testing web application technical security controls and also "
            "provides developers with a list of requirements for secure development.")

    asvs_flat = {}
    asvs_flat2 = {}
    asvs_flat['requirements'] = []
    asvs_flat2['requirements'] = []
    asvs_raw = {}
    language = ''
    mapping_v4 = {}
    mapping_v5 = {}

    rv = json.load(open(os.path.join("templates", "ReqView-ASVS.reqw"), encoding="utf8"))

    def __init__(self, language_in):

        self.language = language_in
        prefix_char1, prefix_char2, prefix_char1_b = self.get_prefix()

        version_regex = re.compile(r'Version (([\d.]+){3})')

        for line in open(os.path.join(self.language, "0x01-Frontispiece.md"), encoding="utf8"):
            m = re.search(version_regex, line)
            if m:
                self.asvs['Version'] = m.group(1)
                break

        about_regex = re.compile('## About the Standard\n\n(.*)')

        with open(os.path.join(self.language, "0x01-Frontispiece.md"), encoding="utf8") as content:
            m = re.search(about_regex, content.read())
            if m:
                self.asvs['Description'] = m.group(1)
                self.rv['description'] = m.group(1)

        # nist_url = "https://pages.nist.gov/800-63-3/sp800-63b.html"
        # req = urllib.request.Request(nist_url)
        # req.add_header('User-Agent', 'Mozilla/5.0')
        # with urllib.request.urlopen(req) as f:
        #     nist_html = f.read().decode()
        # nist_headings = ["".join(h) for h in re.findall(r'<h[34]([^>]*)>(.+)</h[34]>', nist_html)]
        # nist_anchor_map = {}
        # for h in nist_headings:
        #     if secnum := re.findall(r'[1-9A]+\.[0-9\.]+', h):
        #         if a_id := re.findall(r'id="(.+)"', h):
        #             nist_anchor_map[secnum[0]] = a_id[0]
        #         if a_name := re.findall(r'name="(.+)"', h):
        #             nist_anchor_map[secnum[0]] = a_name[0]

        # regex = re.compile(r"\*\*([\d\.]+)\*\*\s\|\s?(.*?)\s?\|")
        # nist_section_map = {}
        # for line in open(os.path.join("mappings", "nist.md"), encoding="utf8"):
        #     m = re.search(regex, line)
        #     if m and m.group(2).strip():
        #         nist_section_map[m.group(1)] = [s.strip() for s in re.split(r"[,/]", m.group(2))]

        # v5be_cwe_map = json.load(open(os.path.join("mappings", "v5.0.be_cwe_mapping.json"), encoding="utf8"))

        # cwe_map = {}
        # regex = re.compile(r"^(v5.+):\s*v5\.0\.0-(\d+\.\d+\.\d+)")
        # for line in open(os.path.join("mappings", "mapping_v5.0.be_to_v5.0.0.yml"), encoding="utf8"):
        #     m = re.search(regex, line)
        #     if m and (cwe_no := v5be_cwe_map.get(m.group(1))):
        #         cwe_map[m.group(2)] = cwe_no


        self.asvs['Requirements'] = chapters = []
        self.asvs_raw['Chapters'] = chapters_raw = []

        rv_doc = self.rv['documents'][0]
        timestamp = datetime.datetime.now(datetime.UTC).isoformat(timespec='milliseconds')[:-6] + "Z"
        rv_doc['createdOn'] = rv_doc['lastChangedOn'] = timestamp

        rv_chapters = rv_doc['data'] = []
        if self.language == 'ar':
            rv_doc['rtl'] = True

        self.rv['attachments'] = {}
        rv_stack = [rv_chapters]

        rv_level = 0

        def rv_parse_md(file, stack, level):
            doc = gfm.parse(open(os.path.join(self.language, file), encoding="utf8").read())
            obj = None
            for e in doc.children:
                t = e.get_type()
                if t == "Heading":
                    if not e.children:
                        continue
                    h_obj = {
                        'heading': e.children[0].children,
                        'children': [],
                        'type': 'INFO'
                    }
                    obj = None
                    if e.level > level:
                        level += 1
                    else:
                        while e.level < level:
                            stack.pop()
                            level -= 1
                        if e.level == level:
                            stack.pop()
                    stack[-1].append(h_obj)
                    stack.append(h_obj['children'])
                elif t != "BlankLine":
                    if obj is None:
                        obj = {
                            'text': "",
                            'type': 'INFO'
                        }
                        stack[-1].append(obj)
                    if e.children:
                        for img in [c for c in e.children if c.get_type() == "Image"]:
                            if img.dest.startswith("https://"):
                                stream = urllib.request.urlopen(img.dest)
                            else:
                                stream = open(os.path.join(self.language, img.dest), "rb")
                            att_id = os.path.basename(img.dest)
                            if 'attachments' not in obj:
                                obj['attachments'] = []
                            obj['attachments'].append(att_id)
                            b64_data = base64.b64encode(stream.read())
                            self.rv['attachments'][att_id] = {'data': "data:image/png;base64," + b64_data.decode()}

                        e.children = [c for c in e.children if c.get_type() != "Image"]
                    html = gfm.render(e)
                    if html and html != "<p></p>\n":
                        obj['text'] += self.rv_html(html)
            return level

        for file in sorted(os.listdir(self.language)):

            if re.match(r"0x0\d-.+\.md$", file):
                rv_level = rv_parse_md(file, rv_stack, rv_level)

            if re.match(r"0x\d{2}-V", file):
                chapter = {}
                chapter_raw = {}
                chapter['Shortcode'] = ""
                chapter['Ordinal'] = ""
                chapter['ShortName'] = ""
                chapter['Name'] = ""
                chapter_raw['Filename'] = file
                chapter_raw['Name'] = ""
                chapter['Items'] = []

                # never used by rv
                rv_chapter = {
                    'type': 'CHAP',
                    'asvsId': "",
                    'ord': "",
                    'heading': "",  # ShortName
                    'children': []
                }

                section = {}
                section_raw = {}
                section['Shortcode'] = ""
                section['Ordinal'] = ""
                section['Name'] = ""
                section_raw['Name'] = ""
                section['Items'] = []

                # never used by rv
                rv_section = {
                    'type': 'SEC',
                    'shortcode': "",
                    'ord': "",
                    'heading': "",  # Name
                    'children': []
                }

                # The filename_regex is used to match filenames that follow the pattern:
                # "0xNN-VNNN-Name", where NN is a two-digit number, VNNN is a chapter number,
                # and Name is a string that does not contain a dot or hyphen.
                filename_regex = re.compile(r'0x\d{2}-(V([0-9]{1,3}))-(\w[^-.]*)')

                m = re.search(filename_regex, file)
                if m:
                    chapter = {}
                    chapter['Shortcode'] = m.group(1).replace('V', prefix_char1)
                    chapter['Ordinal'] = int(m.group(2))
                    chapter['ShortName'] = m.group(3)
                    chapter['Name'] = ""
                    chapter_raw['Name'] = ""
                    chapter['Items'] = []
                    chapter_raw['Lines'] = []
                    chapter_raw['Sections'] = []

                    rv_chapter = {
                        'type': 'CHAP',
                        'asvsId': chapter['Shortcode'][1:],
                        'ord': chapter['Ordinal'],
                        'heading': chapter['ShortName'],
                        'children': []
                    }

                    '''
                    section = {}
                    section['Shortcode'] = m.group(1).replace('V', prefix_char1)
                    section['Ordinal'] = int(m.group(2))
                    section['Name'] = m.group(3)
                    print(m)
                    section['Items'] = []
                    '''

                    rv_section = {
                        'type': 'SEC',
                        'asvsId': section['Shortcode'][1:],
                        'ord': section['Ordinal'],
                        'heading': section['Name'],
                        'children': []
                    }

                    chapters.append(chapter)
                    chapters_raw.append(chapter_raw)
                    rv_chapters.append(rv_chapter)

                rv_chapter_help_lines = []
                rv_section_help_lines = []
                rv_help_dest = None
                def rv_push_help_line(line):
                    if rv_help_dest and line and not line.startswith("| # |") and line.count(":---") < 3:
                        arr = rv_chapter_help_lines if rv_help_dest == 'chapter' else rv_section_help_lines
                        arr.append(line)
                def rv_render_help():
                    if not rv_help_dest:
                        return
                    arr = rv_chapter_help_lines if rv_help_dest == 'chapter' else rv_section_help_lines
                    if not arr:
                        return
                    lines = "".join(arr)
                    arr.clear()
                    help_text = self.rv_html(gfm(lines), True)
                    if rv_help_dest == 'chapter':
                        rv_chapter['help'] = rv_chapter.get('help', '') + help_text
                    else:
                        rv_section['help'] = rv_section.get('help', '') + help_text

                # This regex matches lines that start with a hash (#) followed by a space,
                # prefix_char1 (usually 'V'), one or two digits, prefix_char1_b (which is usually empty)
                # another space, and then some sort of text
                chapter_heading_regex = re.compile(r"^#\s(%s([0-9]{1,2})%s)\s([\w\s][^\n]*)" % (prefix_char1, prefix_char1_b))

                # section_regex matches section headings in the format "## VNN.NNN Name".
                section_regex = re.compile(r"## (%s[0-9]{1,2}.([0-9]{1,3})) ([\w\s][^\n]*)" % prefix_char2)

                # This regex matches requirement lines with the format:
                # **number** | text | text | text | text | numbers, separated by commas | text, separated by slashes
                # req_regex = re.compile("\*\*([\d\.]+)\*\*\s\|\s{0,1}(.*?)\s{0,1}\|(.*?)\|"
                #                        "(.*?)\|(.*?)\|([0-9,\s]*)\|{0,1}([A-Z0-9/\s,.]*)\|{0,1}")

                req_regex = re.compile(r"\*\*([\d\.]+)\*\*\s\|\s?(.*?)\s?\|([1-3 ]*?)\|([0-9,\s]*)\|?([A-Z0-9\s,.]*)\|?")

                before_reqs = True
                matched_already = False

                for line in open(os.path.join(self.language, file), encoding="utf8"):
                    matched_already = False
                    found_regex = False

                    m = re.search(chapter_heading_regex, line)
                    if m:
                        rv_render_help()
                        rv_help_dest = 'chapter'
                        found_regex = True
                        chapter['Name'] = m.group(3)
                        chapter_raw['Name'] = line
                        chapter_raw['Chapter'] = chapter
                        rv_chapter['heading'] = chapter['Name']

                        matched_already = True

                    m = re.search(section_regex, line)
                    if m:
                        rv_render_help()
                        rv_help_dest = 'section'
                        found_regex = True
                        section = {}
                        section_raw = {}
                        section['Shortcode'] = m.group(1)
                        section['Ordinal'] = int(m.group(2))

                        if self.language == 'ar':
                            section['Ordinal'] = int(m.group(1).split('.')[0].replace(prefix_char2, ''))

                        section['Name'] = m.group(3)
                        section_raw['Section'] = section
                        section_raw['Name']  = line
                        section['Items'] = []
                        section_raw['LinesBeforeReqs'] = []
                        section_raw['LinesAfterReqs'] = []
                        section_raw['Reqs'] = []
                        chapter['Items'].append(section)
                        chapter_raw['Sections'].append(section_raw)
                        before_reqs = True
                        has_cwe = True

                        matched_already = True

                        rv_section = {
                            'type': 'SEC',
                            'asvsId': section['Shortcode'][1:],
                            'ord': section['Ordinal'],
                            'heading': section['Name'],
                            'children': []
                        }

                        rv_chapter['children'].append(rv_section)

                    m = re.search(req_regex, line)
                    if m:
                        found_regex = True
                        before_reqs = False
                        req_flat = {}
                        req_flat2 = {}
                        req_flat2['Section'] = req_flat['chapter_id'] = chapter['Shortcode']
                        req_flat2['Name'] = req_flat['chapter_name'] = chapter['Name']
                        req_flat['section_id'] = section['Shortcode']
                        req_flat['section_name'] = section['Name']

                        req = {}
                        req_flat2['Item'] = req_flat['req_id'] = req['Shortcode'] = prefix_char2 + m.group(1)
                        req['Ordinal'] = int(m.group(1).rsplit('.',1)[1])
                        if self.language == 'ar':
                            req['Ordinal'] = int(m.group(1).split('.')[0])

                        req_flat2['Description'] = req_flat['req_description'] = req['Description'] = m.group(2)

                        level1 = {}
                        level2 = {}
                        level3 = {}

                        int_level = int(m.group(3)) if m.group(3) != ' ' else 99

                        str_l1 = '✓' if int_level <= 1 else '' # m.group(3)
                        str_l2 = '✓' if int_level <= 2 else ''  # m.group(4)
                        str_l3 = '✓' if int_level <= 3 else ''  # m.group(5)


                        req_flat['level1'] = str_l1.strip(' ')
                        req_flat['level2'] = str_l2.strip(' ')
                        req_flat['level3'] = str_l3.strip(' ')

                        level1['Required'] = str_l1.strip() != ''
                        req_flat2['L1'] = ('X' if level1['Required'] else '')
                        level2['Required'] = str_l2.strip() != ''
                        req_flat2['L2'] = ('X' if level2['Required'] else '')
                        level3['Required'] = str_l3.strip() != ''
                        req_flat2['L3'] = ('X' if level3['Required'] else '')

                        level1['Requirement'] = ("Optional" if str_l1.strip('✓ ') == "o" else str_l1.strip(' '))
                        level2['Requirement'] = ("Optional" if str_l2.strip('✓ ') == "o" else str_l2.strip(' '))
                        level3['Requirement'] = ("Optional" if str_l3.strip('✓ ') == "o" else str_l3.strip(' '))

                        req['L1'] = level1
                        req['L2'] = level2
                        req['L3'] = level3

                        req['CWE'] = [int(i.strip()) for i in filter(None, m.group(4).strip().split(','))]
                        req_flat2['CWE'] = req_flat['cwe'] = m.group(4).strip()
                        req['NIST'] = [str(i.strip()) for i in filter(None,m.group(5).strip().split('/'))]
                        req_flat2['NIST'] = req_flat['nist'] = m.group(5).strip()

                        rv_req = {
                            'type': 'REQ',
                            'asvsId': req['Shortcode'][1:],
                            'ord': req['Ordinal'],
                            'text': self.rv_html(gfm(req['Description'])),
                            'applicable': True
                        }
                        # if rv_cwe := cwe_map.get(rv_req['asvsId']):
                        #     rv_req['cwe'] = f'<p><a href="https://cwe.mitre.org/data/definitions/{rv_cwe}.html">{rv_cwe}</a></p>'
                        # nist_sec = nist_section_map.get(rv_req['asvsId'])
                        # if nist_sec:
                        #     rv_nist = " / ".join([f'<a href="{nist_url}#{nist_anchor_map.get(s, "")}">{s}</a>' for s in nist_sec])
                        #     if rv_nist:
                        #         rv_req['nist'] = "<p>" + rv_nist + "</p>"
                        if req['Description'].startswith("[DELETED"):
                            rv_req['deleted'] = True
                        if level1['Requirement'] == "Optional":
                            rv_req['l1'] = "OPT"
                            rv_req['l1text'] = "o"
                        elif level1['Required']:
                            rv_req['l1'] = "REQ"
                            rv_req['l1text'] = level1['Requirement']
                        else:
                            rv_req['l1'] = "NREQ"

                        if level2['Requirement'] == "Optional":
                            rv_req['l2'] = "OPT"
                            rv_req['l2text'] = "o"
                        elif level2['Required']:
                            rv_req['l2'] = "REQ"
                            rv_req['l2text'] = level2['Requirement']
                        else:
                            rv_req['l2'] = "NREQ"

                        if level3['Requirement'] == "Optional":
                            rv_req['l3'] = "OPT"
                            rv_req['l3text'] = "o"
                        elif level3['Required']:
                            rv_req['l3'] = "REQ"
                            rv_req['l3text'] = level3['Requirement']
                        else:
                            rv_req['l3'] = "NREQ"

                        rv_section['children'].append(rv_req)

                        section['Items'].append(req)
                        self.asvs_flat['requirements'].append(req_flat)
                        self.asvs_flat2['requirements'].append(req_flat2)
                        req2 = req.copy()


                        req2['raw_text'] = line
                        req2['has_cwe'] = has_cwe
                        if req2['Description'].startswith('[') and ']' in req2['Description']:
                            mapping, text = req2['Description'].split(']', 1)
                            req2['Mapping'] = mapping.strip('[]').strip()
                            req2['DescriptionClean'] = text.strip()
                        else:
                            req2['Mapping'] = ''
                            req2['DescriptionClean'] = req2['Description']

                        req2 = self.parse_mapping_into_req(req2)

                        section_raw['Reqs'].append(req2)
                        matched_already = True

                    elif not matched_already:
                        if section['Ordinal']:
                            if before_reqs:
                                section_raw['LinesBeforeReqs'].append(line)
                                if '| # |' in line and '| CWE |' not in line:
                                    has_cwe = False
                            else:
                                section_raw['LinesAfterReqs'].append(line)
                        else:
                            chapter_raw['Lines'].append(line)

                    if not found_regex:
                        if re.findall(r'^#+\s', line):
                            rv_render_help()
                            if rv_help_dest == 'section':
                                rv_help_dest = 'chapter'
                        rv_push_help_line(line)

                rv_render_help()
                rv_help_dest = None

            if re.match(r"0x9\d-", file):
                rv_level = rv_parse_md(file, rv_stack, rv_level)


        self.mapping_v4 = dict(sorted(self.mapping_v4.items(), key=lambda x: [int(part) for part in x[0].split('.')]))
        self.mapping_v5 = dict(sorted(self.mapping_v5.items(), key=lambda x: [int(part) for part in x[0].split('.')]))

        # --- Begin v5 export structure creation ---
        self.asvs_v5 = copy.deepcopy(self.asvs)
        self.asvs_flat_v5 = copy.deepcopy(self.asvs_flat)
        self.asvs_flat2_v5 = copy.deepcopy(self.asvs_flat2)
        self._convert_flat_to_single_level(self.asvs_flat_v5['requirements'])
        self._convert_flat_to_single_level(self.asvs_flat2_v5['requirements'])
        self._convert_asvs_to_single_level(self.asvs_v5)
        # --- End v5 export structure creation ---

    def _convert_flat_to_single_level(self, reqs):
        for req in reqs:
            # Remove L1/L2/L3, add L
            level = 3
            if 'level1' in req and req['level1'] == '✓':
                level = 1
            elif 'level2' in req and req['level2'] == '✓':
                level = 2
            elif 'level3' in req and req['level3'] == '✓':
                level = 3
            req['L'] = str(level)
            req.pop('level1', None)
            req.pop('level2', None)
            req.pop('level3', None)
            req.pop('nist', None)
            req.pop('cwe', None)
            req.pop('NIST', None)
            req.pop('CWE', None)
            # For asvs_flat2, also remove L1/L2/L3 if present
            req.pop('L1', None)
            req.pop('L2', None)
            req.pop('L3', None)

    def _convert_asvs_to_single_level(self, asvs_obj):
        # asvs_obj['Requirements'] is a list of chapters
        for chapter in asvs_obj.get('Requirements', []):
            for section in chapter.get('Items', []):
                for req in section.get('Items', []):
                    # Remove L1/L2/L3, add L
                    level = 3
                    if 'L1' in req and req['L1'].get('Required'):
                        level = 1
                    elif 'L2' in req and req['L2'].get('Required'):
                        level = 2
                    elif 'L3' in req and req['L3'].get('Required'):
                        level = 3
                    req['L'] = str(level)
                    req.pop('L1', None)
                    req.pop('L2', None)
                    req.pop('L3', None)
                    req.pop('nist', None)
                    req.pop('cwe', None)
                    req.pop('NIST', None)
                    req.pop('CWE', None)

    def rv_html(self, html, is_help = False):
        html = html.replace("\n", "")
        if is_help:
            def heading_sub(m):
                tag = 'em' if int(m.group(2)) > 2 else 'strong'
                if m.group(1):
                    return f'</{tag}></p>'
                else:
                    return f'<p><{tag}>'
            html = re.sub(r'<(/?)h(\d)>', heading_sub, html)
        if self.language != "ar":
            return html.replace('<table>', '<table style="width: 100%;">').strip()
        def rtl_sub(m):
            tag = m.group(1)
            table_width = ' style="width: 100%;"' if tag == "table" else ""
            return f'<{tag} dir="rtl"{table_width}>'
        return re.sub(r'<(p|[uo]l|table)>', rtl_sub, html).strip()

    def get_new_modification(self):
        new_modification = {}
        new_modification['text'] = ''
        new_modification['ids'] = []
        return new_modification

    def parse_mapping_into_req(self, req):

        mapping = req['Mapping']
        req['status'] = {}
        #req['status']['delete_reason'] = ''
        delete_status = "DELETED"
        if mapping == '':
            pass


        elif delete_status in mapping:

            delete_status_comma = f'{delete_status}, '
            if delete_status_comma in mapping:
                delete_status = delete_status_comma

            req['status']['delete_reason'] = ''
            mapping = mapping.replace(delete_status, '')
            req['status']['content'] = 'DELETED'
            delete_destination_options = ['MERGED TO ', 'DUPLICATE OF ', 'DEPRECATED BY , ']

            for delete_destination_option in delete_destination_options:
                if delete_destination_option in mapping:
                    mapping = mapping.replace(delete_destination_option, '')
                    req['status']['delete_reason'] = delete_destination_option.strip()
                    req['status']['delete_destination_ids'] = mapping.split(',')
                    break

            if req['status']['delete_reason'] == '':
                req['status']['delete_reason'] = mapping.strip()



        #modified_status = "MODIFIED"
        #if f'{modified_status}, ' in mapping:

        #req['status']['content'] = modified_status
        #mapping = mapping.replace(modified_status, '')
        else:
            level_regex = re.compile(r'LEVEL L([1-3]) > L([1-3])')

            req['status']['modifications'] = []

            curr_modification = self.get_new_modification()

            for mapping_token in mapping.split(','):

                found = False
                if mapping_token == '':
                    continue

                m = re.search(level_regex, mapping_token)
                if m:
                    req['status']['level_change'] = f'LEVEL L{m.group(1)} > L{m.group(2)}'
                    continue

                content_options = ['MODIFIED', 'ADDED', 'GRAMMAR']
                for content_option in content_options:
                    if content_option in mapping_token:
                        req['status']['content'] = content_option
                        found = True
                        break

                if found:
                    continue

                destination_options = []
                source_options = []

                source_options = ['SPLIT TO ', 'MOVED TO ', 'MERGED TO ', 'DUPLICATE OF ', 'DEPRECATED BY ']
                destination_options = ['MERGED FROM ', 'MOVED FROM ', 'SPLIT FROM ', 'DEPRECATES ']
                modified_options = destination_options + source_options

                for modified_option in modified_options:
                    if modified_option in mapping_token:
                        if 'text' in curr_modification and curr_modification['text'] != '':
                            req['status']['modifications'].append(curr_modification)

                        curr_modification = self.get_new_modification()
                        curr_modification['text'] = modified_option
                        mapping_token = mapping_token.replace(modified_option, '')
                        curr_modification['ids'].append(mapping_token.strip())
                        found = True
                        break

                if found:
                    continue

                curr_modification['ids'].append(mapping_token.strip())

            if 'text' in curr_modification and curr_modification['text'] != '':
                req['status']['modifications'].append(curr_modification)

        req['status']['v4ids'] = []

        req_id = req['Shortcode'][1:]

        if 'modifications' in req['status'] and len(req['status']['modifications']) > 0:
            for modification in req['status']['modifications']:
                if modification['text'] in source_options:
                    self.mapping_v4 = self.add_if_not_exists(self.mapping_v4, req_id)
                    for id in modification['ids']:
                        mapping_item = {}
                        mapping_item['text'] = modification['text']
                        mapping_item['v5.0.be'] = id
                        mapping_item['direction'] = '4>5'
                        self.mapping_v4[req_id]['mappings'].append(mapping_item)

                elif 'MERGED FROM' in mapping and 'MOVED FROM' not in mapping:
                    self.mapping_v4 = self.add_if_not_exists(self.mapping_v4, req_id)
                    for id in modification['ids']:
                        mapping_item = {}
                        mapping_item['text'] = modification['text']
                        mapping_item['v5.0.be'] = id
                        mapping_item['direction'] = '4>5'
                        self.mapping_v4[req_id]['mappings'].append(mapping_item)

                if modification['text'] in destination_options:
                    self.mapping_v5 = self.add_if_not_exists(self.mapping_v5, req_id)
                    for id in modification['ids']:
                        mapping_item = {}
                        mapping_item['text'] = modification['text']
                        mapping_item['direction'] = '5>4'
                        mapping_item['v4.0.3'] = id
                        self.mapping_v5[req_id]['mappings'].append(mapping_item)


        elif 'content' in req['status'] and 'DELETED' in req['status']['content']:
            self.mapping_v4 = self.add_if_not_exists(self.mapping_v4, req_id)


            if 'delete_destination_ids' in req['status'] and len(req['status']['delete_destination_ids']) > 0:
                for id in req['status']['delete_destination_ids']:

                    mapping_item = {}
                    mapping_item['text'] = req['status']['delete_reason']
                    mapping_item['v5.0.be'] = id
                    mapping_item['direction'] = '4>5'
                    self.mapping_v4[req_id]['mappings'].append(mapping_item)

            else:
                mapping_item = {}
                mapping_item['text'] = req['status']['delete_reason']
                mapping_item['v5.0.be'] = ''
                mapping_item['direction'] = '4>5'
                self.mapping_v4[req_id]['mappings'].append(mapping_item)

        elif 'content' in req['status'] and ('MODIFIED' in req['status']['content'] or 'GRAMMAR' in req['status']['content']):

            self.mapping_v4 = self.add_if_not_exists(self.mapping_v4, req_id)
            mapping_item = {}
            mapping_item['text'] = req['status']['content']
            mapping_item['v5.0.be'] = req_id
            mapping_item['direction'] = '4>5'
            self.mapping_v4[req_id]['mappings'].append(mapping_item)


            self.mapping_v5 = self.add_if_not_exists(self.mapping_v5, req_id)
            mapping_item = {}
            mapping_item['text'] = req['status']['content']
            mapping_item['direction'] = '5>4'
            mapping_item['v4.0.3'] = req_id
            self.mapping_v5[req_id]['mappings'].append(mapping_item)

        elif 'level_change' in req['status']:

            self.mapping_v4 = self.add_if_not_exists(self.mapping_v4, req_id)
            mapping_item = {}
            mapping_item['text'] = req['status']['level_change']
            mapping_item['v5.0.be'] = req_id
            mapping_item['direction'] = '4>5'
            self.mapping_v4[req_id]['mappings'].append(mapping_item)


            self.mapping_v5 = self.add_if_not_exists(self.mapping_v5, req_id)
            mapping_item = {}
            mapping_item['text'] = req['status']['level_change']
            mapping_item['direction'] = '5>4'
            mapping_item['v4.0.3'] = req_id
            self.mapping_v5[req_id]['mappings'].append(mapping_item)
        elif mapping == '':
            self.mapping_v4 = self.add_if_not_exists(self.mapping_v4, req_id)


        return req

    #if f'{modified_status}' in mapping:
    #    req['status']['content'] = modified_status
    #    return req

    #return req

    def add_if_not_exists(self, dict_in, key):
        if key not in dict_in:
            dict_in[key] = {}
            dict_in[key]['mappings'] = []

        return dict_in



    def status_to_text(self, status):
        status_text = ''

        comma = ''

        if 'content' in status:
            if status['content'] == 'DELETED':
                #return ''
                status_text = f'{status["content"]}'

                if status["delete_reason"] != '':
                    status_text += f', {status["delete_reason"]}'
                if  'delete_destination_ids' in status and status["delete_destination_ids"] != []:
                    status_text += f' {",".join(status["delete_destination_ids"])}'

            elif status['content'] != '':
                status_text = f'{status["content"]}'
                comma = ', '

        if 'modifications' in status:
            for modification in status['modifications']:
                status_text += f'{comma}{modification["text"]}{", ".join(modification["ids"])}'
                comma = ', '

        if 'level_change' in status:
            status_text += f'{comma}{status["level_change"]}'

        if status_text == '':
            return status
        else:
            return f'[{status_text}]'




    def print_raw_requirement(self, req):
        ret_str = ''
        description = f'{req["DescriptionClean"]}'


        if req['Mapping'] != '':

            if 'status' in req:
                description = f'{self.status_to_text(req["status"])} {description}'
            else:
                description = 'PARSING ERROR'#f'[{req["Mapping"]}] {description}'



        ret_str =  (f'| **{req["Shortcode"][1:]}** '
            f'| {description.strip()} '
            f'| {self.pad_if_set(req["L1"]["Requirement"])}'
            f'| {self.pad_if_set(req["L2"]["Requirement"])}'
            f'| {self.pad_if_set(req["L3"]["Requirement"])}|'
        )

        if req['has_cwe']:
            ret_str += f' {self.pad_if_set(" ".join(map(str, req["CWE"])))}|'

        return f'{ret_str}\n'

    def pad_if_set(self, string):
        if len(string) > 0:
            return string + ' '
        return string

    def get_prefix(self):
        prefix_char1 = prefix_char2 = 'V'
        prefix_char1_b = ''
        if self.language == 'ar':
            prefix_char1 = 'ت'
            prefix_char1_b = ':'
            prefix_char2 = 'ق'



        return prefix_char1, prefix_char2, prefix_char1_b

    def to_raw(self, output_folder):
        ''' Returns the raw data '''
        str_return = ''

        str_chapter = ''
        for chapter in self.asvs_raw['Chapters']:
            #str_chapter = chapter['Name']
            str_chapter = f"# V{chapter['Chapter']['Ordinal']} {chapter['Chapter']['Name']}\n"
            for line in chapter['Lines']:
                str_chapter += line
            for section in chapter['Sections']:
                #str_chapter += section['Name']

                # This is a silly hack for the first section that was moved for V1
                if 'V1' in section['Name']:
                    str_chapter += section['Name']
                else:
                    str_chapter += f"## V{chapter['Chapter']['Ordinal']}.{section['Section']['Ordinal']} {section['Section']['Name']}\n"
                for line in section['LinesBeforeReqs']:
                    str_chapter += line
                for req in section['Reqs']:
                    #if len(req['raw_text']) != len(self.print_raw_requirement(req)):
                    #str_chapter += req['raw_text']
                    str_chapter += self.print_raw_requirement(req)
                for line in section['LinesAfterReqs']:
                    str_chapter += line

            if output_folder != '':
                with open(os.path.join(output_folder, chapter['Filename']), 'w', encoding='utf-8') as f:
                    f.write(str_chapter)
            else:
                str_return += str_chapter

        return str_return

    def to_v4_mapping(self):
        return self.mapping_to_csv(self.mapping_v4)
        #return json.dumps(self.mapping_v4, indent = 2, sort_keys = False, ensure_ascii=False).strip()

    def to_v5_mapping(self):
        return self.mapping_to_csv(self.mapping_v5)
        #return json.dumps(self.mapping_v5, indent = 2, sort_keys = False, ensure_ascii=False).strip()

    def mapping_to_csv(self, mapping):

        mapping_lines = []

        for key, req in mapping.items():
            #print(key)
            mapping_found = False
            for mapping_item in req['mappings']:
                mapping_line = {}
                mapping_line['action'] = mapping_item['text'].strip()

                if '4>5' in mapping_item['direction']:
                    mapping_line['v4.0.3'] = key
                    mapping_line['v5.0.be'] = mapping_item['v5.0.be']

                elif '5>4' in mapping_item['direction']:
                    mapping_line['v4.0.3'] = mapping_item['v4.0.3']
                    mapping_line['v5.0.be'] = key

                mapping_found = True
                mapping_lines.append(mapping_line)

            if not mapping_found:
                mapping_line = {}
                mapping_line['v4.0.3'] = key
                mapping_lines.append(mapping_line)

        si = StringIO()

        writer = csv.DictWriter(si, ['v4.0.3', 'action', 'v5.0.be'])
        writer.writeheader()
        writer.writerows(mapping_lines)

        return si.getvalue()

    def to_json_legacy(self):
        ''' Returns a JSON-formatted string '''
        return json.dumps(self.asvs, indent = 2, sort_keys = False, ensure_ascii=False).strip()

    def to_json_xl(self):
        ''' Returns a JSON-formatted string '''
        return json.dumps(self.asvs_raw['Chapters'], indent = 2, sort_keys = False, ensure_ascii=False).strip()

    def to_reqw_json(self):
        return json.dumps(self.rv, indent = 2, sort_keys = False, ensure_ascii=False).strip()

    def to_json_flat_legacy(self):
        ''' Returns a JSON-formatted string which is flattened and simpler '''
        return json.dumps(self.asvs_flat, indent = 2, sort_keys = False, ensure_ascii=False).strip()

    def to_json(self):
        ''' Returns a JSON-formatted string (new default)  '''
        return json.dumps(self.asvs_v5, indent = 2, sort_keys = False, ensure_ascii=False).strip()


    def to_json_flat(self):
        ''' Returns a JSON-formatted string which is flattened and simpler (new default)  '''
        return json.dumps(self.asvs_flat_v5, indent = 2, sort_keys = False, ensure_ascii=False).strip()

    def to_xmlOLD(self):
        ''' Returns XML '''
        xml = ''

        for r in self.requirements:

            xml += "<requirement id = \"" + escape(r['id']) + "\">" + escape(r['text']) + "</requirement>\n"

        return xml
    def to_xml_legacy(self):
        return dicttoxml(self.asvs, attr_type=False).decode('utf-8')

    def to_xml(self):
        ''' Returns XML for v5 (single L) '''
        return dicttoxml(self.asvs_v5, attr_type=False).decode('utf-8')

    def to_csv_legacy(self):
        ''' Returns CSV '''
        si = StringIO()

        writer = csv.DictWriter(si, ['chapter_id', 'chapter_name', 'section_id', 'section_name', 'req_id', 'req_description', 'level1', 'level2', 'level3', 'cwe', 'nist'])
        writer.writeheader()
        writer.writerows(self.asvs_flat['requirements'])

        return si.getvalue()

    def to_csv(self):
        ''' Returns CSV for v5 (single L) (new default) '''
        si = StringIO()
        writer = csv.DictWriter(si, ['chapter_id', 'chapter_name', 'section_id', 'section_name', 'req_id', 'req_description', 'L'])
        writer.writeheader()
        writer.writerows(self.asvs_flat_v5['requirements'])
        return si.getvalue()

    def dict_increment(self, dict_obj, dict_key):
        if dict_key not in dict_obj:
            dict_obj[dict_key] = 0

        dict_obj[dict_key] += 1

        return dict_obj

    def summary_total(self, summary):
        total = 0
        for chapter in summary:
            total += summary[chapter]

        return total

    def summary_string(self, format, summary):
        return f'Language: {self.language}. Format: {format}. Total: {self.summary_total(summary)}. Details: {summary}\n'


    def verify_csv(self, csv):

        prefix_char1, null, null = self.get_prefix()

        summary = {}
        for line in csv.splitlines():
            if 'chapter_id,chapter_name' not in line:
                summary = self.dict_increment(summary, line.split(',')[0].replace(prefix_char1,''))

        return self.summary_string('csv', summary)

    def verify_json_flat(self, json_flat):
        prefix_char1, null, null = self.get_prefix()
        data = json.loads(json_flat)
        summary = {}
        for req in data['requirements']:
            summary = self.dict_increment(summary, req['chapter_id'].replace(prefix_char1,''))

        return self.summary_string('json_flat', summary)

    def verify_json(self, json_reg):
        prefix_char1, null, null = self.get_prefix()
        data = json.loads(json_reg)
        summary = {}
        for req in data['Requirements']:
            for ite1 in req['Items']:
                for ite2 in ite1['Items']:
                    summary = self.dict_increment(summary, req['Shortcode'].replace(prefix_char1,''))

        return self.summary_string('json', summary)


    def verify_xml(self, xml_string):
        prefix_char1, null, null = self.get_prefix()
        data = ET.fromstring(xml_string)
        summary = {}
        scode = ''
        for req in data.iter():
            if req.tag == 'Requirements':
                for el_item in req:
                    for el_item_sub in el_item:
                        if el_item_sub.tag == 'Shortcode':
                            scode = el_item_sub.text
                        if el_item_sub.tag == 'Items':
                            for el_Items in el_item_sub:
                                for el_item2_sub in el_Items:
                                    if el_item2_sub.tag == 'Items':
                                        for el_Items2 in el_item2_sub:
                                            summary = self.dict_increment(summary, scode.replace(prefix_char1,''))

        return self.summary_string('xml', summary)
