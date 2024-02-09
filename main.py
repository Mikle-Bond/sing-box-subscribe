import json, os, tool, time, requests, sys, urllib, importlib, yaml, ruamel.yaml
import re, tempfile
from typing import Optional, Tuple, List, Union, Callable, Any, Generator, Iterable, Iterator
from typing_extensions import Literal
from functools import cached_property
from datetime import datetime
from urllib.parse import urlparse
from pathlib import Path
from parsers.clash2base64 import clash2v2ray
from parsers import module_to_dict
from pydantic import BaseModel, Field, AliasPath


parsers_mod = module_to_dict()
providers = None
color_code = [31, 32, 33, 34, 35, 36, 91, 92, 93, 94, 95, 96]

Tag = str
Url = str
Node = dict[str, Any]
NodeMultiMap = dict[Tag, list[Node]]
StringTransform = Callable[[str], str]
FilterAction = Literal['include', 'exclude']

def filter_true(it: Iterable[Any]) -> Iterable[Any]:
    return filter(lambda _:_, it)

class Subscription(BaseModel):
    url: Url
    tag: Tag
    enabled: bool = True
    emoji: int = 0
    subgroup: str = ''
    prefix: str = ''
    ua: str = Field(default='v2rayng', alias='User-Agent')

class ASOD(BaseModel):
    proxy: Tag = ''
    direct: Tag = ''

class ProvidersConfig(BaseModel):
    subscribes: List[Subscription]
    config_template: Url = ''
    auto_set_outbounds_dns: ASOD = Field(default_factory=ASOD)
    save_config_path: Path = Path('config.json')
    auto_backup: bool = False
    exclude_protocol: str = 'ssr'
    only_nodes: bool = Field(default=False, alias='Only-Nodes')

class SBLog(BaseModel):
    level: str = "warning"
    timestamp: bool = False
class SBClashFile(BaseModel):
    enabled: bool = False
    store_fakeip: bool = False
class SBClashAPI(BaseModel):
    default_mode: str = 'rule'
    external_controller: str = '127.0.0.1:9090'
    external_ui: str = 'ui'
    external_ui_download_detour: str = 'direct'
    external_ui_download_url: Url = 'https://mirror.ghproxy.com/https://github.com/MetaCubeX/Yacd-meta/archive/gh-pages.zip'
    secret: str = ''
class SBExperimentalClashAPI(BaseModel):
    clash_file: SBClashFile = Field(default_factory=SBClashFile)
    clash_api: SBClashAPI = Field(default_factory=SBClashAPI)
class SBExperimental(BaseModel):
    experimental: SBExperimentalClashAPI = Field(default_factory=SBExperimentalClashAPI)

SBDnsRule = dict
example = [{'domain': ['ghproxy.com',
                       'cdn.jsdelivr.net',
                       'testingcf.jsdelivr.net'],
            'server': 'localDns'},
           {'rule_set': 'geosite-category-ads-all', 'server': 'block'},
           {'disable_cache': True,
            'outbound': 'any',
            'server': 'localDns'},
           {'rule_set': 'geosite-cn', 'server': 'localDns'},
           {'clash_mode': 'direct', 'server': 'localDns'},
           {'clash_mode': 'global', 'server': 'proxyDns'},
           {'rule_set': 'geosite-geolocation-!cn',
            'server': 'proxyDns'}]
class SBDnsServer(BaseModel):
    tag: Tag
    address: Url
    detour: Optional[Tag] = None
class SBDns(BaseModel):
    strategy: str = 'auto'
    final: Tag
    rules: list[SBDnsRule]
    servers: list[SBDnsServer]
SBInbound = dict[str, Any]

class SBOutboundFilter(BaseModel):
    for_: list[Tag] = Field(default_factory=list, alias='for')
    action: FilterAction = 'include'
    keywords: Optional[list[str]] = None

    @cached_property
    def pattern(self, /) -> Optional[re.Pattern]:
        good_keywords = filter_true(map(str.strip, keywords))
        query = '|'.join(good_keywords)
        if not query:
            return
        return re.compile(query)

    def apply_on(self, tags: Iterable[Tag]) -> Iterable[Tag]:
        invert = (action == 'exclude')
        return filter(lambda x: invert ^ bool(self.pattern.search(x)), tags)

class SBOutbound(BaseModel):
    outbounds: Union[None,Tag,list[Tag]] = None
    tag: Tag
    type: str
    default: Optional[Tag] = None
    filter: Optional[list[SBOutboundFilter]] = None
    
class SBRuleSetExemplar(BaseModel):
    download_detour: Tag = 'direct'
    format: str = 'binary'
    tag: Optional[Tag] = None
    type: str = 'remote'
    url: Url

Domain = Url
class SBRouteRule(BaseModel):
    outbound: Tag
    network: Optional[str] = None
    protocol: Optional[str] = None
    port: Optional[int] = None
    rule_set: Optional[Union[Tag, list[Tag]]] = None
    clash_mode: Optional[str] = None
    domain: Optional[list[Domain]] = None


class SBRoute(BaseModel):
    auto_detect_interface: bool = False
    final: Optional[Tag] = None
    rule_set: Optional[list[SBRuleSetExemplar]] = None
    rules: list[SBRouteRule]


class SingBoxConfig(BaseModel):
    log: SBLog = Field(default_factory=SBLog)
    experimental: SBExperimental = Field(default_factory=SBExperimental)
    dns: SBDns = Field(default_factory=SBDns)
    route: SBRoute = Field(default_factory=SBRoute)
    inbounds: list[SBInbound]
    outbounds: list[SBOutbound]

default_settings = ProvidersConfig.model_validate({
    "subscribes":[
        {
            "url": "Please, fill in URL",
            "tag": "tag_1",
            "enabled": True,
            "emoji": 1,
            "subgroup": "",
            "prefix": "",
            "User-Agent":"v2rayng"
        },
        {
            "url": "URL",
            "tag": "tag_2",
            "enabled": False,
            "emoji": 0,
            "subgroup": "命名/named",
            "prefix": "❤️",
            "User-Agent":"clashmeta"
        }
    ]
})

def loop_color(text):
    text = '{color}m{text}'.format(color=color_code[0], text=text)
    color_code.append(color_code.pop(0))
    return text


def get_template():
    template_dir = 'config_template'  # 配置模板文件夹路径
    template_files = os.listdir(template_dir)  # 获取文件夹中的所有文件
    template_list = [os.path.splitext(file)[0] for file in template_files if
                     file.endswith('.json')]  # 移除扩展名并过滤出以.json结尾的文件
    template_list.sort()  # 对文件名进行排序
    return template_list


def process_subscribes(subscribes: list[Subscription]) -> dict[Tag, list[Node]]:
    nodes = {}
    for subscribe in subscribes:
        if not subscribe.enabled:
            continue
        if 'sing-box-subscribe.vercel.app' in subscribe.url:
            continue
        _nodes: list[Node] = get_nodes(subscribe.url)
        if not _nodes:
            print("No urls found in subscription, skipping")
            # print('没有在此订阅下找到节点，跳过')
            # print('Không tìm thấy proxy trong link thuê bao này, bỏ qua')
            continue
        prefix = subscribe.prefix
        if prefix:
            rename_nodes(_nodes, lambda x: prefix + x)
        if subscribe.emoji:
            rename_nodes(_nodes, tool.rename)
        if subscribe.subgroup:
            subscribe.tag = subscribe.tag + '-' + subscribe.subgroup + '-' + 'subgroup'
        if not nodes.get(subscribe.tag):
            nodes[subscribe.tag] = []
        nodes[subscribe.tag] += _nodes
    tool.proDuplicateNodeName(nodes)
    return nodes


def rename_nodes(nodes: list[dict], rule: Callable[[str], str]) -> None:
    for node in nodes:
        node['tag'] = rule(node['tag'])
        if node.get('detour'):
            node['detour'] = rule(node['detour'])


def get_nodes(url: Url) -> list[Node]:
    if url.startswith('sub://'):
        url = tool.b64Decode(url[6:]).decode('utf-8')
    urlstr = urlparse(url)

    if urlstr.scheme:
        content = get_content_from_url(url)
    else:
        try:
            content = tool.b64Decode(url).decode('utf-8')
            return process_content(content)
        except:
            content = get_content_form_file(url)
    # print (content)
    if type(content) != dict: 
        #? assert type(content) == str
        return process_content(content)

    assert type(content) == dict
    if 'proxies' in content:
        share_links = []
        for proxy in content['proxies']:
            share_links.append(clash2v2ray(proxy))
        data = '\n'.join(share_links)
        return process_content(data)
    elif 'outbounds' in content:
        outbounds = []
        excluded_types = {"selector", "urltest", "direct", "block", "dns"}
        filtered_outbounds = [outbound for outbound in content['outbounds'] if outbound.get("type") not in excluded_types]
        outbounds.extend(filtered_outbounds)
        return outbounds
    assert False, "We reached something that should not be reachable"
    return []


def process_content(content: str) -> list[Node]:
    # firstline = tool.firstLine(content)
    # # print(firstline)
    # if not get_parser(firstline):
    #     return None
    nodelist = []
    for url in content.splitlines():
        nodelist.extend(nodes_generator(url))
    return nodelist


def nodes_generator(url: Url) -> Generator[Node, None, None]:
    url = url.strip()
    if not url:
        return
    factory = get_parser(url)
    if not factory:
        return
    node = factory(url)
    if not node:
        return
    if isinstance(node, tuple):
        # 处理shadowtls
        yield node[0]
        yield node[1]
    else:
        yield node


def get_parser(node: Url) -> "function":
    """
    get node specification (Url encoded)
    return function for parsing it 

    def parse(url: Url) -> Optional[Node]:
        return ...
    """
    proto = tool.get_protocol(node)
    if providers.exclude_protocol:
        eps = providers.exclude_protocol.split(',')
        if len(eps) > 0:
            eps = [protocol.strip() for protocol in eps]
            if proto in eps:
                return None
    if not proto or proto not in parsers_mod.keys():
        return None
    return parsers_mod[proto].parse


def get_content_from_url(url: Url, n: int = 6) -> list[Url]:
    UA = ''
    print('处理: ' + url)
    # print('Đang tải link đăng ký: ' + url + '')
    prefixes = ["vmess://", "vless://", "ss://", "ssr://", "trojan://", "tuic://", "hysteria://", "hysteria2://",
                "hy2://", "wg://", "http2://", "socks://", "socks5://"]
    if any(url.startswith(prefix) for prefix in prefixes):
        return list(filter_true(map(str.strip, url.splitlines())))
    '''
    for subscribe in providers["subscribes"]:
        if 'enabled' in subscribe and not subscribe['enabled']:
            continue
        if subscribe['url'] == url:
            UA = subscribe.get('User-Agent', '')
    response = tool.getResponse(url, custom_user_agent=UA)
    '''
    response = tool.getResponse(url)
    concount = 1
    while concount <= n and not response:
        print(f'连接出错，正在进行第 {concount} 次重试，最多重试 {n} 次...')
        # print('Lỗi kết nối, đang thử lại '+str(concount)+'/'+str(n)+'...')
        response = tool.getResponse(url)
        concount = concount + 1
        time.sleep(1)
    if not response:
        print('获取错误，跳过此订阅')
        # print('Lỗi khi tải link đăng ký, bỏ qua link đăng ký này')
        print('----------------------------')
        return []
    response_content = response.content
    response_text = response_content.decode('utf-8-sig')  # utf-8-sig 可以忽略 BOM
    #response_encoding = response.encoding
    if response_text.isspace():
        print('没有从订阅链接获取到任何内容')
        # print('Không nhận được proxy nào từ link đăng ký')
        return None
    if not response_text:
        response = tool.getResponse(url, custom_user_agent='clashmeta')
        response_text = response.text
    assert isinstance(response_text, str)
    if any(response_text.startswith(prefix) for prefix in prefixes):
        response_text = tool.noblankLine(response_text)
        return response_text
    elif 'proxies' in response_text:
        yaml_content = response.content.decode('utf-8')
        yaml = ruamel.yaml.YAML()
        try:
            response_text = dict(yaml.load(yaml_content))
            return response_text
        except:
            pass
    elif 'outbounds' in response_text:
        try:
            response_text = json.loads(response.text)
            return response_text
        except:
            pass
    else:
        try:
            response_text = tool.b64Decode(response_text)
            response_text = response_text.decode(encoding="utf-8")
            # response_text = bytes.decode(response_text,encoding=response_encoding)
        except:
            pass
            # traceback.print_exc()
    return response_text


def get_content_form_file(file: Path) -> list[Url]:
    print('处理: ' + file + '')
    file = Path(file)
    # print('Đang tải link đăng ký: ' + file + '')
    # encoding = tool.get_encoding(file)
    file_extension = file.suffix.lower()
    if file_extension == '.yaml':
        content = file.read_text()
        yaml_data = dict(yaml.safe_load(content))
        share_links = []
        for proxy in yaml_data['proxies']:
            share_links.append(clash2v2ray(proxy))
        node = list(link.strip() for link in share_links if link)
        return node
    else:
        data = file.read_text(encoding='utf-8')
        clean_lines = map(str.strip, data.split())
        nonempty_lines = filter_true(clean_lines)
        return list(nonempty_lines)


def try_save_file(path: Path, content: str) -> bool:
    if path.exists():
        path.unlink()
        print(f"已删除文件，并重新保存：m{path}")
    else:
        print(f"文件不存在，正在保存：m{path}")
    path.write_text(content, encoding='utf-8')


def save_config(path: Path, config: SingBoxConfig) -> None:
    tmp = Path(tempfile.gettempdir())
    if providers.auto_backup:
        now = datetime.now().strftime('%Y%m%d%H%M%S')
        if path.exists():
            backup = tmp / f'{path.name}.{now}.bak'
            path.replace(target)
    content = config.model_dump_json(indent=2, exclude_none=True)
    try_save_file(path, content)


def set_proxy_rule_dns(config: SingBoxConfig):
    # dns_template = {
    #     "tag": "remote",
    #     "address": "tls://1.1.1.1",
    #     "detour": ""
    # }
    dns_tags = set( server.tag for server in config.dns.servers )
    asod = providers.auto_set_outbounds_dns
    if not set(dns_tags).issuperset(set((asod.proxy, asod.direct))):
        return
    config_rules = config.route.rules
    outbound_dns = []
    dns_rules = config.dns.rules
    for rule in config_rules:
        if rule.outbound in ['block', 'dns-out']:
            continue
        if rule.outbound != 'direct':
            outbounds_dns_template = \
                list(filter(lambda server: server.tag == asod.proxy, config.dns.servers))[0]
            dns_obj = outbounds_dns_template.copy()
            dns_obj.tag = rule.outbound + '_dns'
            dns_obj.detour = rule.outbound
            if dns_obj not in outbound_dns:
                outbound_dns.append(dns_obj)
        if rule.type == 'logical':
            dns_rule_obj = {
                'type': 'logical',
                'mode': rule.mode,
                'rules': [],
                'server': rule.outbound + '_dns' if rule.outbound != 'direct' else asod.direct
            }
            def gen(x):
                for _rule in x:
                    r = pro_dns_from_route_rules(_rule)
                    if r:
                        yield r
            dns_rule_obj_rules = list(gen(rule.rules))
            if dns_rule_obj_rules:
                dns_rule_obj.rules = dns_rule_obj_rules
            else:
                dns_rule_obj = None
        else:
            dns_rule_obj = pro_dns_from_route_rules(rule)
        if dns_rule_obj:
            dns_rules.append(dns_rule_obj)
    # 清除重复规则
    _dns_rules = []
    for dr in dns_rules:
        if dr not in _dns_rules:
            _dns_rules.append(dr)
    config.dns.rules = _dns_rules
    config.dns.servers.extend(outbound_dns)


def pro_dns_from_route_rules(route_rule: dict) -> dict:
    dns_route_same_list = ["inbound", "ip_version", "network", "protocol", 'domain', 'domain_suffix', 'domain_keyword',
                           'domain_regex', 'geosite', "source_geoip", "source_ip_cidr", "source_port",
                           "source_port_range", "port", "port_range", "process_name", "process_path", "package_name",
                           "user", "user_id", "clash_mode", "invert"]
    dns_rule_obj = { k: v for k, v in route_rule.items() if k in dns_route_same_list }
    if len(dns_rule_obj) == 0:
        return None
    if route_rule.outbound:
        dns_rule_obj.server = route_rule.outbound + '_dns' if route_rule.outbound != 'direct' else \
            providers.auto_set_outbounds_dns.direct
    return dns_rule_obj


def action_keywords(tags: Iterable[Tag], action: FilterAction, keywords: list[str]) -> Iterable[Tag]:
    # filter将按顺序依次执行
    # "filter":[
    #         {"action":"include","keywords":[""]},
    #         {"action":"exclude","keywords":[""]}
    #     ]
    '''
    # 空关键字过滤
    '''
    # Join the patterns list into a single pattern, separated by '|'
    good_keywords = filter_true(map(str.strip, keywords))
    query = '|'.join(good_keywords)

    # If the combined pattern is empty or only contains whitespace, return the original tags
    if not query:
        return tags

    # Compile the combined regex pattern
    pattern = re.compile(query)

    invert = (action == 'exclude')
    return filter(lambda x: invert ^ bool(pattern.search(x)), tags)

def pro_tag_template(tags: Iterable[Tag], config_outbound: SBOutbound, group_tag: Tag) -> Iterable[Tag]:
    for f in config_outbound.filter or []:
        if group_tag not in f.for_:
            continue
        tags = f.apply_on(tags)
    return tags

def pro_node_template(nodes: Iterable[Node], config_outbound: SBOutbound, group_tag: Tag) -> Iterable[Tag]:
    tags = (node['tag'] for node in nodes)
    return pro_tag_template(tags, config_outbound, group_tag)

def is_outbound_group(item: str) -> bool:
    return item.startswith('{') and item.endswith('}')

def strip_brakets(item: str) -> str:
    if is_outbound_group(item):
        return item[1:-1]
    return item

def tag_from_group(group: str) -> str:
    # return (group.rsplit("-", 1)[0]).rsplit("-", 1)[-1]
    return group.rsplit("-", 2)[-2]

def gen_temp_outbounds(data: NodeMultiMap, config_outbounds: list[SBOutbound]) -> None:
    if not config_outbounds:
        return

    # 提前处理all模板
    for out in config_outbounds:
        # 处理出站
        if not out.outbounds:
            continue

        if '{all}' in out.outbounds:
            o1 = []
            for item in out.outbounds:
                if item != '{all}':
                    o1.append(strip_brakets(item))
            out.outbounds = o1

        t_o = gen_single_temp_outbound(data, out)

        if len(t_o) == 0:
            message = '发现 {} 出站下的节点数量为 0 ，会导致sing-box无法运行，请检查config模板是否正确。'
            raise RuntimeError(message.format(out.tag))

        out.outbounds = t_o
        out.filter = None


def gen_single_temp_outbound(data: NodeMultiMap, sb_outbound: SBOutbound):
    retval = []
    check_dup = []
    for otag in sb_outbound.outbounds:
        # 避免添加重复节点
        if otag in check_dup:
            continue
        check_dup.append(otag)

        # 处理模板
        if not is_outbound_group(otag):
            retval.append(otag)
            continue

        otag = otag[1:-1]

        if data.get(otag):
            nodes = data[otag]
            retval.extend(pro_node_template(nodes, sb_outbound, otag))
            continue
        
        if otag != 'all':
            continue

        for group, nodes in data.items():
            retval.extend(pro_node_template(nodes, sb_outbound, group))

    return retval


def combin_to_config(config: SingBoxConfig, data: NodeMultiMap) -> SingBoxConfig:
    config_outbounds = config.outbounds
    subgroups_counter = 0
    for group in data:
        if 'subgroup' in group:
            subgroups_counter += 1

        for out in config_outbounds:
            if not out.outbounds:
                continue
            if out.tag == 'proxy':
                continue
            out.outbounds = [out.outbounds] if isinstance(out.outbounds, Tag) else out.outbounds

            if 'subgroup' not in group:
                out.outbounds.append('{' + group + '}')
            elif '{all}' not in out.outbounds:
                out.outbounds.insert(subgroups_counter, tag_from_group(group))
            else:
                index_of_all = out.outbounds.index('{all}')
                out.outbounds[index_of_all] = tag_from_group(group)
                subgroups_counter += 1

        if 'subgroup' in group:
            new_outbound = {'tag': tag_from_group(group), 'type': 'selector', 'outbounds': ['{' + group + '}']}
            config_outbounds.insert(-4, new_outbound)

    temp_outbounds = []
    gen_temp_outbounds(data, config_outbounds)
    for group in data:
        temp_outbounds.extend(data[group])

    config.outbounds = config_outbounds + temp_outbounds
    # 自动配置路由规则到dns规则，避免dns泄露
    set_proxy_rule_dns(config)
    return config


def updateLocalConfig(local_host, path):
    header = {
        'Content-Type': 'application/json'
    }
    r = requests.put(local_host + '/configs?force=false', json={"path": path}, headers=header)
    print(r.text)


def display_template(tl):
    print_str = ''
    for i in range(len(tl)):
        print_str += loop_color('{index}, {name} '.format(index=i + 1, name=tl[i]))
    print(print_str)


def select_config_template(tl, selected_template_index=None):
    while True:
        uip = input('输入序号，载入对应config模板（直接回车默认选第一个配置模板）：')
        if uip == '':
            return 0
        try:
            uip = int(uip)
        except:
            continue
        if 1 <= uip <= len(lt):
            return uip - 1
        print('输入了错误信息！重新输入')


def main_convert(providers: ProvidersConfig, config: SingBoxConfig) -> SingBoxConfig:
    nodes: dict[Tag, list[Node]] = process_subscribes(providers.subscribes)

    if not providers.only_nodes:
        return combin_to_config(config, nodes)  # 节点信息添加到模板

    combined_contents = []
    for sub_tag, contents in nodes.items():
        # 遍历每个机场的内容
        for content in contents:
            # 将内容添加到新列表中
            combined_contents.append(content)
    return combined_contents  # 只返回节点信息
    # updateLocalConfig('http://127.0.0.1:9090',providers['save_config_path'])


def get_config_from_url(url: Url) -> dict:
    print('选择: ' + url + '')
    response = requests.get(url)
    response.raise_for_status()
    return response.json()


def get_config_from_file(templates: list[dict], index: int):
    display_template(templates)
    config_template_path = 'config_template/' + templates[index] + '.json'
    print('选择: ' + templates[index] + '.json')
    return SingBoxConfig.model_validate_json(tool.readFile(config_template_path))


def main(providers_string: str, template_index: int) -> int:
    global providers
    if not providers_string:
        providers_file = Path('providers.json')
        if not providers_file.is_file():
            print("provide --temp_json_data or populate providers.json")
            return 1
        providers_string = providers_file.read_text()

    try:
        providers = ProvidersConfig.model_validate_json(providers_string) 
    except ValueError as e:
        print("Providers config could not be parsed")
        print(str(e))
        return 2

    config_src = providers.config_template

    if config_src:
        config = get_config_from_url(config_src)
    else:
        template_list = get_template()
        if len(template_list) < 1:
            print('没有找到模板文件')
            # print('Không tìm thấy file mẫu')
            return 1
        config = get_config_from_file(template_list, template_index)
    print(config.model_dump_json(exclude_none=True, indent=2))
    final_config = main_convert(providers, config)
    path = Path(providers.save_config_path)
    save_config(path, final_config)

    return 0


if __name__ == '__main__':
    # 自定义函数，用于解析参数为 JSON 格式
    def parse_json(value):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            raise argparse.ArgumentTypeError(f"Invalid JSON: {value}")

    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--temp_json_data', type=str, help='临时内容')
    parser.add_argument('--template_index', type=int, help='模板序号')
    args = parser.parse_args()

    sys.exit(main(args.temp_json_data, args.template_index))

