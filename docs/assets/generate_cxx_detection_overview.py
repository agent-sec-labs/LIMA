"""Editable overview based on current LIMA code; style follows overview2.drawio."""
from pathlib import Path
import xml.etree.ElementTree as E

OUT = Path(__file__).parent
mx = E.Element('mxfile', host='Electron')
d = E.SubElement(mx, 'diagram', id='lima-cxx-overview', name='C++ 漏洞检测流程')
model = E.SubElement(d, 'mxGraphModel', grid='1', gridSize='10', page='1', pageWidth='1720', pageHeight='810', background='#FFFFFF', math='0', shadow='0')
r = E.SubElement(model, 'root')
E.SubElement(r, 'mxCell', id='0')
E.SubElement(r, 'mxCell', id='1', parent='0')
base = 'whiteSpace=wrap;html=1;fontFamily=Microsoft YaHei;fontSize=17;fontColor=#263238;'

def box(i, value, x, y, w, h, fill, parent='1', extra=''):
    c = E.SubElement(r, 'mxCell', id=i, value=value, parent=parent, vertex='1', style=base+'rounded=1;arcSize=15;strokeColor=none;shadow=1;fillColor='+fill+';'+extra)
    E.SubElement(c, 'mxGeometry', x=str(x), y=str(y), width=str(w), height=str(h), attrib={'as':'geometry'})
    return i

def label(i, value, x, y, w, h, parent='1', color='#263238', size=19):
    return box(i,value,x,y,w,h,'none',parent,f'shadow=0;fontSize={size};fontColor={color};')

def text(title, body, color):
    return f'<b>{title}</b><br><br><font style="font-size:14px;color:{color};">{body}</font>'

def edge(i,s,t,label='',color='#4F6472',ports='',points=(), dashed=False):
    c=E.SubElement(r,'mxCell',id=i,source=s,target=t,parent='1',edge='1',value=label,style='edgeStyle=orthogonalEdgeStyle;rounded=1;orthogonalLoop=1;jettySize=auto;html=1;strokeWidth=2.5;endArrow=classic;endFill=1;fontFamily=Microsoft YaHei;fontSize=13;labelBackgroundColor=#FFFFFF;fontColor='+color+';strokeColor='+color+';'+ports+('dashed=1;' if dashed else ''))
    g=E.SubElement(c,'mxGeometry',relative='1',attrib={'as':'geometry'})
    if points:
        arr=E.SubElement(g,'Array',attrib={'as':'points'})
        for x,y in points:E.SubElement(arr,'mxPoint',x=str(x),y=str(y))

label('title','<b>LIMA · C++ 漏洞检测流程</b>',380,15,960,45,size=27)
label('subtitle','静态线索 → 智能体调查 → 假设与实验闭环 → 证据分级与报告',300,65,1120,30,color='#60717D',size=16)
box('triage','',175,120,350,460,'#EEF6FC',extra='container=1;pointerEvents=0;arcSize=12;')
box('investigate','',545,120,685,460,'#F3EFF8',extra='container=1;pointerEvents=0;arcSize=12;')
box('final','',1250,120,285,460,'#EEF7EE',extra='container=1;pointerEvents=0;arcSize=12;')
label('h1','<b>线索发现与侦察</b>',10,12,330,34,'triage','#315A78',21)
label('h2','<b>深度分析与复现闭环</b>',10,12,665,34,'investigate','#5C4774',21)
label('h3','<b>证据裁决与报告</b>',5,12,275,34,'final','#486B47',21)
box('input',text('C / C++ 源码','仓库 / PR 快照<br>源码与构建上下文<br>绑定 snapshot_hash','#4F6472'),15,225,135,170,'#FFFFFF',extra='shape=document;boundedLbl=1;fontSize=18;')
box('seed',text('静态分诊','工具 / 事实候选<br>无候选时 Discovery<br>有界读码发现线索','#315A78'),20,110,140,170,'#D9ECF8','triage')
box('scout',text('Scout 智能体','搜索 · 读码 · 追踪<br>排除 / 升级线索<br>形成目标清单','#315A78'),190,110,140,170,'#CDEBF3','triage')
label('leadnote','线索仅用于引导调查，不直接认定漏洞',15,325,320,70,'triage','#315A78',14)
box('specialist',text('Specialist','分析生命周期 / 数据流<br>提出漏洞假设与 CWE<br>生成 PoC 驱动','#5C4774'),25,110,185,170,'#DDD4EA','investigate')
box('repro',text('复现工作台','隔离沙箱编译与运行<br>ASan / UBSan 观察<br>绑定目标与漏洞类型','#315A78'),260,110,210,170,'#D9ECF8','investigate')
box('critic',text('Critic 智能体','寻找反证与替代解释<br>修正假设 / PoC<br>拒绝或停止调查','#8A4052'),260,320,210,125,'#F7D7DF','investigate')
# Runtime qualification is labeled on the evidence edge.
label('loopnote','有界迭代<br>轮次 / 预算 / 超时约束',25,55,185,45,'investigate','#5C4774',14)
box('arbiter',text('证据裁决','汇合假设、反证与工具证据<br>冻结状态机判定<br>冲突 → 人工复核','#486B47'),25,110,235,130,'#CFE8CF','final')
box('grade',text('发现分级','semantic-supported<br>fact-verified<br>runtime-confirmed<br>needs-human-review','#486B47'),25,270,235,145,'#E3F1E3','final')
box('output',text('检测报告','位置 · CWE · 触发条件<br>证据与 PoC 执行记录<br>rejected / abstain 留审计<br><br>检测结果不自动修复','#7B6122'),1560,225,145,220,'#FFFFFF',extra='shape=document;boundedLbl=1;fontSize=18;')
box('support','',175,645,1360,130,'#FBE1C6',extra='container=1;pointerEvents=0;arcSize=15;')
label('supporttitle','<b>工具与执行支撑</b>',400,8,560,30,'support','#A45E23',20)
label('facts','<b>静态与事实仪器</b><br>Semgrep · Clang · Build Context<br>UAF 事实 / P1–P7 证明（可选）',15,46,440,72,'support','#755334',14)
label('sandbox','<b>复现沙箱</b><br>Docker · Landlock · seccomp<br>身份、资源预算与超时限制',470,46,415,72,'support','#755334',14)
label('audit','<b>证据与审计</b><br>快照身份 · 实验台账 · 产物哈希<br>共享调用预算与降级记录',920,46,425,72,'support','#755334',14)
edge('e1','input','seed',ports='exitX=1;exitY=0.5;entryX=0;entryY=0.5;')
edge('e2','seed','scout',ports='exitX=1;exitY=0.5;entryX=0;entryY=0.5;')
edge('e3','scout','specialist',ports='exitX=1;exitY=0.5;entryX=0;entryY=0.5;')
edge('e4','specialist','repro','假设 + PoC','#5C4774','exitX=1;exitY=0.5;entryX=0;entryY=0.5;')
edge('e5','repro','arbiter','目标与漏洞类型匹配<br>运行命中','#639763','exitX=1;exitY=0.5;entryX=0;entryY=0.5;')
edge('e6','repro','critic','未命中 / 实验失败','#AE6176','exitX=0.5;exitY=1;entryX=0.5;entryY=0;')
edge('e7','critic','specialist','修正后再试','#675181','exitX=0;exitY=0.5;entryX=0.5;entryY=1;',[(665,502)])
edge('e8','critic','arbiter','收敛 / 拒绝 / 达到上限','#AE6176','exitX=1;exitY=0.5;entryX=0.5;entryY=0;',[(1215,502),(1215,180),(1392,180)])
edge('e9','arbiter','grade',color='#486B47',ports='exitX=0.5;exitY=1;entryX=0.5;entryY=0;')
edge('e10','grade','output',color='#639763',ports='exitX=1;exitY=0.5;entryX=0;entryY=0.75;')
edge('e11','facts','seed','候选线索','#D78231','exitX=0;exitY=0.5;entryX=0;entryY=0.8;',[(165,727),(165,488)],True)
edge('e12','sandbox','repro','受控实验','#D78231','exitX=1;exitY=0.5;entryX=1;entryY=0.8;',[(1165,727),(1165,610),(1040,610),(1040,366)],True)
edge('e13','audit','arbiter','证据绑定','#D78231','exitX=1;exitY=0.5;entryX=1;entryY=0.75;',[(1545,730),(1545,328)],True)
label('boundary','整仓模式支持动态复现；diff-only 或复现不可用时降级汇报。工具证据用于裁决，不能替代智能体假设。',200,785,1310,24,color='#60717D',size=13)
E.indent(mx,space='  ')
E.ElementTree(mx).write(OUT/'cxx_detection_overview.drawio',encoding='utf-8',xml_declaration=True)
print(OUT/'cxx_detection_overview.drawio')


