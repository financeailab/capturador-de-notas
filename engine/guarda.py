"""Guarda em tempo de execucao do capturador (audit hook, PEP 578).

Instalado so quando o capturador.py roda como programa, antes de importar terceiro
(docs/superpowers/specs/2026-11-09-capturador-guarda-design.md no monorepo financeailab).
Regra 1: codigo compilado de texto nao chama, nao importa e nao grava fora do proprio quadro, em nenhum nivel, fora
dos geradores medidos; e nao carrega biblioteca nativa (ctypes) enquanto estiver na pilha.
Regra 2: rede so para o ADN na 443; processo so a linha do agendar, no Windows.
O 1o bloqueio liga uma trava: dali em diante texto, rede e processo barram. Sai com SystemExit(4).
O estado so tem valores imutaveis, religados pelas funcoes deste modulo: o texto alcanca objetos sem chamar, e o
Pydantic chama o resultado com zero argumento (um dict.clear zeraria a trava). Sem flag de reentrancia global: o
DNS do proprio guarda e reconhecido pelo quadro, e o evento de outra thread nunca passa sem a politica.
Limite aceito (superficie 2, .py direto de uma dependencia comprometida, nao o texto do Pydantic): um hook em
processo nao confina codigo .py arbitrario. Esse .py carrega ctypes sem texto na pilha ou cria um sub-interpretador
(sem evento de audit no 3.13+) e escapa da camada de audit. Criar qualquer um exige um CALL, barrado na superficie 1.
Tambem superficie 2: os carve-outs (_GERADORES, _FIND_LIB, _SUBPROCESSO) casam o quadro por sufixo de caminho, entao
uma dependencia comprometida que plante um arquivo em .../ply/lex.py, .../dataclasses.py ou .../ctypes/util.py cairia
na lista confiavel. Alcancar esses quadros ja exige rodar .py proprio (superficie 2); o texto do Pydantic nao os forja.
Fora de escopo (como escrita em disco, por decisao do dono): LEITURA de memoria do processo via ctypes.string_at/
wstring_at/cast (wrappers Python que o call-schema do Pydantic aceita). Nao e carga de codigo nem exfiltracao - sair
com o que leu ainda exige rede (barrada) ou processo (barrado). ctypes.memmove/memset (ESCRITA = ACE) nao sao
alcancaveis: sao CFunctionType que o Pydantic recusa como schema (teste de regressao prende isso; pydantic pinado <3).
"""
import hashlib
import opcode
import os
import re
import socket
import sys

HOSTS = ("adn.nfse.gov.br", "adn.producaorestrita.nfse.gov.br")  # copia de engine/adn.py; o teste prova a igualdade
PORTA = 443
_PROIBIDOS = frozenset(v for k, v in opcode.opmap.items() if k.startswith(("CALL", "IMPORT_")) or (
    k.startswith(("STORE_", "DELETE_")) and "FAST" not in k and "DEREF" not in k))
_GERADORES = frozenset({  # (fim do caminho com '/', funcao) de quem chama exec/eval; medidos no 3.12 e no 3.14
    ("/dataclasses.py", "_create_fn"),
    ("/dataclasses.py", "add_fns_to_class"),
    ("/collections/__init__.py", "namedtuple"),
    ("/typing_inspection/typing_objects.py", "_compile_isinstance_check_function"),
    ("/typing_inspection/typing_objects.py", "_compile_identity_check_function"),
    ("/ply/lex.py", "readtab"),  # ply vendorizado no pycparser 2.x (cffi -> keyring): carrega a tabela por exec('import ...')
    ("/ply/yacc.py", "read_table"),
})
_SUBPROCESSO = ("/subprocess.py", "_execute_child")  # quem chama o _winapi.CreateProcess de um Popen
_SUFIXOS = frozenset({s for s, _ in _GERADORES} | {_SUBPROCESSO[0]})
_SEMPRE = frozenset({
    "os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.startfile", "os.fork", "os.forkpty", "pty.spawn",
    "socket.bind", "socket.sendto", "socket.sendmsg", "socket.gethostbyaddr", "socket.getnameinfo",
    "sqlite3.enable_load_extension", "sqlite3.load_extension", "mmap.__new__", "webbrowser.open", "urllib.Request",
    "ftplib.connect", "smtplib.connect", "poplib.connect", "imaplib.open", "nntplib.connect",
})
_SIMBOLO = frozenset({"ctypes.dlsym", "ctypes.dlsym/handle"})  # consulta de simbolo (sem carga de codigo): so no-texto
_NATIVO = frozenset({"ctypes.dlopen"}) | _SIMBOLO  # dlopen (carga de lib = ACE): so em import real (_carga_no_import)
_DRIVERS_IMPORT = frozenset({"_load_unlocked", "exec_module", "create_module"})  # motor do import, sob o corpo do
# modulo; FORA: _call_with_frames_removed e _find_and_load[_unlocked] recebem um callback (import_) que a forja via
# call-schema do Pydantic usa para disparar a carga com um driver na pilha. _load_unlocked/exec_module/create_module
# so recebem spec/module (forjar = objeto vivo no input = superficie 2).
_FIND_LIB = frozenset({"_findSoname_ldconfig", "_findLib_gcc", "_findLib_ld", "_get_soname",
                       "_findLib_crle", "find_library"})  # funcoes do ctypes.util que criam processo p/ achar lib
_DNS = frozenset({"socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyname_ex"})
_TRAVADOS = _DNS | {"socket.connect", "http.client.connect", "subprocess.Popen", "_winapi.CreateProcess"}
_COM_QUADRO = _NATIVO | _DNS | {"exec", "_winapi.CreateProcess", "subprocess.Popen"}
_LINHA = re.compile(r'schtasks /Create /F /SC DAILY /TN capturador-de-notas-[0-9a-f]{8} '
                    r'/ST ((?:[01]\d|2[0-3]):[0-5]\d) /TR .* --pasta \\"([^"]*)\\""')

_instalado = False
_trava = False
_ficha = False
_cap = ""
_dbus = ()
_ips = frozenset()


def _aspas(arg):
    """O escape do subprocess.list2cmdline para um argumento com espaco (o teste compara com o original)."""
    saida, barras = ['"'], 0
    for c in arg:
        if c == "\\":
            barras += 1
            continue
        saida.append("\\" * (barras * 2 + 1) + c if c == '"' else "\\" * barras + c)
        barras = 0
    return "".join(saida) + "\\" * (barras * 2) + '"'


def linha_do_agendar(pasta, hora, executavel, capturador):
    """A linha que o subprocess.Popen audita no Windows para a lista do agendar (capturador.py, agendar)."""
    nome = "capturador-de-notas-" + hashlib.sha256(pasta.lower().encode("utf-8")).hexdigest()[:8]
    fim = "\\" if pasta.endswith("\\") else ""
    comando = '"' + executavel + '" "' + capturador + '" baixar --pasta "' + pasta + fim + '"'
    return "schtasks /Create /F /SC DAILY /TN " + nome + " /ST " + hora + " /TR " + _aspas(comando)


def _e_agendar(args, executavel, capturador):
    if len(args) != 4 or args[0] is not None or args[2] is not None or args[3] is not None:
        return False
    linha = args[1]
    m = _LINHA.fullmatch(linha) if isinstance(linha, str) and capturador else None
    if m is None:
        return False
    hora, p = m.group(1), m.group(2)
    base = p.rstrip("\\")
    barras = len(p) - len(base)
    return any(linha_do_agendar(base + "\\" * n, hora, executavel, capturador) == linha
               for n in range(barras + 1))


def enderecos_dbus(valor):
    """Os sockets AF_UNIX do barramento de sessao: unix:path=P e unix:abstract=N; com escape '%', nenhum."""
    saida = []
    for entrada in valor.split(";"):
        tipo, _, resto = entrada.partition(":")
        campos = dict(c.split("=", 1) for c in resto.split(",") if "=" in c)
        if tipo != "unix" or "%" in resto:
            continue
        if "path" in campos:
            saida.append(campos["path"])
        elif "abstract" in campos:
            saida.append("\0" + campos["abstract"])
    return tuple(saida)


def _texto_proibido(co):
    if any(op in _PROIBIDOS for op in co.co_code[::2]):
        return True
    return any(_texto_proibido(c) for c in co.co_consts if isinstance(c, type(co)))


def _de_texto(nome):
    return not (nome.endswith(".py") or nome.startswith("<frozen"))


def decidir(evento, args, chamador=None, estado=None, nativo_ok=False, find_lib=False):
    """Rotulo do bloqueio, ou None; 'resolver', 'ficha' e 'gastar' pedem acao ao hook. Pura: nao instala nada.
    `estado` so nos testes: (trava, ficha, cap, dbus, ips)."""
    trava, ficha, cap, dbus, ips = (_trava, _ficha, _cap, _dbus, _ips) if estado is None else estado
    if evento == "exec":
        if not _de_texto(args[0].co_filename):
            return None
        if trava:
            return "trava"
        if chamador in _GERADORES or not _texto_proibido(args[0]):
            return None
        return "texto"
    if evento in _SEMPRE:
        return "proibido"
    if evento in _NATIVO:
        return None if nativo_ok and not trava else "nativo"  # carga nativa so durante import de modulo (_na_importacao)
    if evento in _TRAVADOS and trava:
        return "trava"
    if evento in _DNS:
        host = args[0].decode("ascii", "replace") if isinstance(args[0], bytes) else args[0]
        host = host.lower().rstrip(".") if isinstance(host, str) else None
        porta = args[1] if evento == "socket.getaddrinfo" else PORTA
        return "resolver" if host in HOSTS and porta in (PORTA, str(PORTA)) else "rede"
    if evento == "socket.connect":
        alvo = args[1]
        if isinstance(alvo, tuple) and len(alvo) >= 2 and alvo[0] in ips and alvo[1] == PORTA:
            return None
        if isinstance(alvo, bytes):
            alvo = alvo.decode("utf-8", "replace")
        return None if isinstance(alvo, str) and alvo in dbus else "rede"
    if evento == "http.client.connect":
        host = args[1].lower().rstrip(".") if isinstance(args[1], str) else args[1]  # mesma normalizacao do DNS
        return None if host in HOSTS and args[2] == PORTA else "rede"
    if evento == "subprocess.Popen":
        if os.name == "nt" and _e_agendar(args, sys.executable, cap):
            return "ficha"
        return None if find_lib else "processo"  # find_lib: ldconfig/gcc do ctypes.util, sem texto (ver _do_find_library)
    if evento == "_winapi.CreateProcess":
        return "gastar" if ficha and chamador == _SUBPROCESSO else "processo"
    return None


def _quem(quadro):
    """(fim do caminho, funcao) do quadro, com '/' em qualquer sistema; o caminho inteiro se nao e um sufixo conhecido."""
    arquivo, funcao = quadro.f_code.co_filename.replace("\\", "/"), quadro.f_code.co_name
    for sufixo in _SUFIXOS:
        if arquivo.endswith(sufixo):
            return (sufixo, funcao)
    return (arquivo, funcao)


def _texto_na_pilha(quadro):
    while quadro is not None:
        if _de_texto(quadro.f_code.co_filename):
            return True
        quadro = quadro.f_back
    return False


def _carga_no_import(quadro):
    """ctypes.dlopen (carga de lib = risco de ACE) so durante import real de modulo: ha quadro de DRIVER do import
    (_DRIVERS_IMPORT) na pilha, nao o trampolim _call_with_frames_removed, que e forjavel (roda um callable com um
    quadro <frozen importlib> na pilha sem importar nada). Texto em qualquer ponto barra. O dlsym (consulta de simbolo,
    sem carga de codigo) nao passa por aqui: basta nao ter texto (o backend macOS do keyring resolve simbolo em runtime)."""
    achou = False
    while quadro is not None:
        nome = quadro.f_code.co_filename
        if _de_texto(nome):
            return False
        if nome.startswith("<frozen importlib") and quadro.f_code.co_name in _DRIVERS_IMPORT:
            achou = True
        quadro = quadro.f_back
    return achou


def _do_guarda(quadro):
    """O DNS vem da resolucao do proprio guarda (o quadro do socket.getaddrinfo ou o de cima e o _resolver)."""
    for _ in range(3):
        if quadro is None:
            return False
        if quadro.f_code.co_name == "_resolver" and quadro.f_code.co_filename == __file__:
            return True
        quadro = quadro.f_back
    return False


def _do_find_library(quadro):
    """O ctypes.util.find_library cria processo (ldconfig/gcc/ld/objdump) para localizar lib nativa no Linux; o
    keyring e o cryptography fazem isso. Libera so quando vem desses quadros E sem texto em NENHUM ponto da pilha
    (read-only). Varre a pilha inteira: texto em qualquer lugar barra, mesmo acima do quadro do ctypes.util."""
    achou = False
    while quadro is not None:
        nome = quadro.f_code.co_filename
        if _de_texto(nome):
            return False
        if quadro.f_code.co_name in _FIND_LIB and nome.replace("\\", "/").endswith("/ctypes/util.py"):
            achou = True
        quadro = quadro.f_back
    return achou


def _resolver(hosts):
    """Acumula os IPs dos hosts; o que nao resolve fica de fora (o connect para ele barra)."""
    global _ips
    novos = set(_ips)
    for host in hosts:
        try:
            infos = socket.getaddrinfo(host, PORTA, proto=socket.IPPROTO_TCP)
        except OSError:
            continue
        novos.update(i[4][0] for i in infos)
    _ips = frozenset(novos)


def _gancho(evento, args):
    global _ficha, _trava
    if evento == "exec" and not _de_texto(args[0].co_filename):
        return  # o import de um .py nao precisa de quadro (evita ler f_code a cada import e o evento aninhado dele)
    quadro = sys._getframe(1) if evento in _COM_QUADRO else None
    if evento in _DNS and _do_guarda(quadro):
        return
    chamador = _quem(quadro) if evento in ("exec", "_winapi.CreateProcess") else None
    if evento == "ctypes.dlopen":
        nativo_ok = _carga_no_import(quadro)
    elif evento in _SIMBOLO:
        nativo_ok = not _texto_na_pilha(quadro)
    else:
        nativo_ok = False
    rotulo = decidir(evento, args, chamador, None, nativo_ok,
                     evento == "subprocess.Popen" and _do_find_library(quadro))
    if rotulo == "resolver":
        _resolver((args[0],))
        return
    if rotulo == "rede" and evento == "socket.connect" and not _trava:
        _resolver(HOSTS)  # o DNS pode ter mudado entre a resolucao do guarda e a do http.client
        rotulo = decidir(evento, args)
    if rotulo in ("ficha", "gastar"):
        _ficha = rotulo == "ficha"
        return
    if rotulo is None:
        return
    _trava, _ficha = True, False
    sys.stderr.write("guarda: bloqueou " + rotulo + "\n")
    raise SystemExit(4)


def bloqueou():
    return _trava


def instalar(capturador):
    global _instalado, _cap, _dbus
    if _instalado:
        return
    _instalado, _cap = True, str(capturador)
    _dbus = enderecos_dbus(os.environ.get("DBUS_SESSION_BUS_ADDRESS", ""))
    sys.addaudithook(_gancho)
