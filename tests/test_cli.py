"""CLI: configurar, baixar e agendar; V3 (trava entre processos), V4 (saida sem dado), V5 (segredo)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import types
from pathlib import Path

import keyring
import keyring.backend
import keyring.backends.fail
import keyring.errors
import pytest

import capturador
from engine import adn, rodada
from tests.sinteticos import CNPJ_A, CNPJ_B, MARCADOR, SENHA, ADNFalso, envelope, ilegivel, nfse_xml, pfx

MOTOR = Path(capturador.__file__).resolve().parent


class Cofre(keyring.backend.KeyringBackend):
    priority = 1

    def __init__(self):
        super().__init__()
        self.dados = {}

    def set_password(self, servico, usuario, senha):
        self.dados[(servico, usuario)] = senha

    def get_password(self, servico, usuario):
        return self.dados.get((servico, usuario))

    def delete_password(self, servico, usuario):
        self.dados.pop((servico, usuario), None)


@pytest.fixture
def cofre():
    anterior = keyring.get_keyring()
    c = Cofre()
    keyring.set_keyring(c)
    yield c
    keyring.set_keyring(anterior)


@pytest.fixture
def pasta(tmp_path):
    p = tmp_path / "Minhas Notas"
    p.mkdir()
    return p


def _pfx(tmp_path, cnpj=CNPJ_A, dias=365) -> Path:
    arq = tmp_path / "certificados" / f"{cnpj}.pfx"
    arq.parent.mkdir(exist_ok=True)
    arq.write_bytes(pfx(cnpj, dias=dias))
    return arq


def _configurar(monkeypatch, pasta, arq, cnpj=CNPJ_A, senha=SENHA) -> int:
    monkeypatch.setattr(capturador.getpass, "getpass", lambda _p: senha)
    return capturador.configurar(pasta, cnpj, str(arq))


def _adn_falso(monkeypatch, falso):
    monkeypatch.setattr(adn, "contexto_tls", lambda cert: None)
    monkeypatch.setattr(adn, "obter_pagina", lambda ctx, cnpj, nsu: falso(cnpj, nsu))


# ---------- configurar ----------

def test_configurar_guarda_a_senha_no_cofre_e_nao_no_json(monkeypatch, cofre, pasta, tmp_path, capsys):
    assert _configurar(monkeypatch, pasta, _pfx(tmp_path)) == 0
    assert cofre.dados == {("capturador-de-notas", CNPJ_A): SENHA}
    cfg = json.loads((pasta / "capturador.json").read_text(encoding="utf-8"))
    assert [e["cnpj"] for e in cfg["empresas"]] == [CNPJ_A] and SENHA not in json.dumps(cfg)
    assert SENHA not in "".join(capsys.readouterr())


def test_configurar_aceita_filial_da_mesma_raiz_e_recusa_outra_raiz(monkeypatch, cofre, pasta, tmp_path):
    arq = _pfx(tmp_path)
    assert _configurar(monkeypatch, pasta, arq, cnpj="11222333000262") == 0
    assert _configurar(monkeypatch, pasta, arq, cnpj=CNPJ_B) == 2


@pytest.mark.parametrize("caso", ["senha", "vencido", "cnpj"])
def test_configurar_recusa_com_codigo_2(monkeypatch, cofre, pasta, tmp_path, caso):
    arq = _pfx(tmp_path, dias=-1 if caso == "vencido" else 365)
    cnpj = "123" if caso == "cnpj" else CNPJ_A
    assert _configurar(monkeypatch, pasta, arq, cnpj=cnpj, senha="errada" if caso == "senha" else SENHA) == 2
    assert cofre.dados == {} and not (pasta / "capturador.json").exists()


def test_configurar_recusa_cofre_sem_armazenamento_seguro(monkeypatch, pasta, tmp_path):
    anterior = keyring.get_keyring()
    keyring.set_keyring(keyring.backends.fail.Keyring())
    try:
        assert _configurar(monkeypatch, pasta, _pfx(tmp_path)) == 2
    finally:
        keyring.set_keyring(anterior)
    assert not (pasta / "capturador.json").exists()


def test_configurar_recusa_pasta_dentro_de_repositorio(monkeypatch, cofre, tmp_path):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    assert _configurar(monkeypatch, repo / "notas", _pfx(tmp_path)) == 2


def test_configurar_nao_sobrescreve_json_invalido(monkeypatch, cofre, pasta, tmp_path):
    (pasta / "capturador.json").write_text("{quebrado", encoding="utf-8")
    assert _configurar(monkeypatch, pasta, _pfx(tmp_path)) == 2
    assert (pasta / "capturador.json").read_text(encoding="utf-8") == "{quebrado"


def test_configurar_aceita_caminho_colado_com_aspas_no_prompt(monkeypatch, cofre, pasta, tmp_path):
    arq = _pfx(tmp_path)
    respostas = iter([CNPJ_A, f'"{arq}"'])
    monkeypatch.setattr("builtins.input", lambda _p: next(respostas))
    monkeypatch.setattr(capturador.getpass, "getpass", lambda _p: SENHA)
    assert capturador.configurar(pasta, None, None) == 0


def test_configurar_falha_ao_gravar_preserva_config_e_senha_anteriores(monkeypatch, cofre, pasta, tmp_path):
    assert _configurar(monkeypatch, pasta, _pfx(tmp_path)) == 0
    antes = (pasta / "capturador.json").read_bytes()
    nova = tmp_path / "nova.pfx"
    nova.write_bytes(pfx(senha="senha-nova"))

    def disco_falha(*_a):
        raise OSError("disco cheio simulado")

    monkeypatch.setattr(capturador.os, "replace", disco_falha)
    assert _configurar(monkeypatch, pasta, nova, senha="senha-nova") == 2
    assert (pasta / "capturador.json").read_bytes() == antes
    assert cofre.dados[("capturador-de-notas", CNPJ_A)] == SENHA
    assert not list(pasta.glob("*.tmp"))


def test_configurar_cofre_que_recusa_gravar_sai_com_2_sem_config(monkeypatch, cofre, pasta, tmp_path):
    def travado(*_a):
        raise keyring.errors.PasswordSetError("cofre travado simulado")

    monkeypatch.setattr(cofre, "set_password", travado)
    assert _configurar(monkeypatch, pasta, _pfx(tmp_path)) == 2
    assert not (pasta / "capturador.json").exists()


# ---------- baixar ----------

def test_baixar_cofre_travado_na_1a_empresa_nao_para_a_2a(monkeypatch, cofre, pasta, tmp_path, capsys):
    _configurar(monkeypatch, pasta, _pfx(tmp_path))
    _configurar(monkeypatch, pasta, _pfx(tmp_path, CNPJ_B), cnpj=CNPJ_B)
    original = cofre.get_password

    def travado_na_a(servico, usuario):
        if usuario == CNPJ_A:
            raise keyring.errors.KeyringLocked(f"{MARCADOR} travado")
        return original(servico, usuario)

    monkeypatch.setattr(cofre, "get_password", travado_na_a)
    _adn_falso(monkeypatch, ADNFalso({CNPJ_B: [envelope(1, nfse_xml(1, prest=CNPJ_B))]}))
    capsys.readouterr()
    assert capturador.baixar(pasta) == 1
    out, err = capsys.readouterr()
    assert "FALHOU (KeyringLocked)" in out and "notas novas 1" in out and MARCADOR not in out + err
    assert (pasta / "notas.csv").exists()
    assert "notas novas 1" in (pasta / "capturador.log").read_text(encoding="utf-8")

def test_baixar_matriz_e_filial_com_o_mesmo_pfx(monkeypatch, cofre, pasta, tmp_path, capsys):
    arq, filial = _pfx(tmp_path), "11222333000262"
    _configurar(monkeypatch, pasta, arq)
    _configurar(monkeypatch, pasta, arq, cnpj=filial)
    falso = ADNFalso({CNPJ_A: [envelope(1, nfse_xml(1))], filial: [envelope(4, nfse_xml(2, toma=filial))]})
    _adn_falso(monkeypatch, falso)
    assert capturador.baixar(pasta) == 0
    assert sorted(c for c, _ in falso.chamadas) == [CNPJ_A, filial]
    assert capsys.readouterr().out.count("notas novas 1") == 2

def test_baixar_ponta_a_ponta_v4_v5_sem_dado_nem_segredo_na_saida(monkeypatch, cofre, pasta, tmp_path, capsys):
    _configurar(monkeypatch, pasta, _pfx(tmp_path))
    capsys.readouterr()
    _adn_falso(monkeypatch, ADNFalso({CNPJ_A: [envelope(i, nfse_xml(i)) for i in range(1, 4)]}))
    assert capturador.baixar(pasta) == 0
    out, err = capsys.readouterr()
    log = (pasta / "capturador.log").read_text(encoding="utf-8")
    assert "notas novas 3" in out and "notas novas 3" in log
    for canal in (out, err, log):
        assert MARCADOR not in canal and CNPJ_A not in canal and SENHA not in canal
    # V5: nenhum arquivo da pasta leva a senha nem chave privada
    for arq in pasta.rglob("*"):
        if arq.is_file():
            dados = arq.read_bytes()
            assert SENHA.encode() not in dados and b"PRIVATE KEY" not in dados, arq.name


def test_baixar_empresa_que_falha_nao_para_as_outras(monkeypatch, cofre, pasta, tmp_path, capsys):
    _configurar(monkeypatch, pasta, _pfx(tmp_path))
    _configurar(monkeypatch, pasta, _pfx(tmp_path, CNPJ_B), cnpj=CNPJ_B)
    del cofre.dados[("capturador-de-notas", CNPJ_A)]  # senha ausente na 1a empresa
    capsys.readouterr()
    _adn_falso(monkeypatch, ADNFalso({CNPJ_B: [envelope(1, nfse_xml(1, prest=CNPJ_B))]}))
    assert capturador.baixar(pasta) == 1
    out = capsys.readouterr().out
    assert "FALHOU (senha ausente no cofre" in out and "notas novas 1" in out


def test_baixar_pendencia_nova_sai_com_1_e_antiga_com_0(monkeypatch, cofre, pasta, tmp_path, capsys):
    _configurar(monkeypatch, pasta, _pfx(tmp_path))
    falso = ADNFalso({CNPJ_A: [envelope(1, nfse_xml(1)), ilegivel(2)]})
    _adn_falso(monkeypatch, falso)
    assert capturador.baixar(pasta) == 1
    assert capturador.baixar(pasta) == 0
    assert "total 1" in capsys.readouterr().out


def test_baixar_sem_configuracao_sai_com_2(pasta):
    assert capturador.baixar(pasta) == 2


def test_baixar_avisa_certificado_perto_de_vencer(monkeypatch, cofre, pasta, tmp_path, capsys):
    _configurar(monkeypatch, pasta, _pfx(tmp_path, dias=10))
    _adn_falso(monkeypatch, ADNFalso({}))
    assert capturador.baixar(pasta) == 0
    assert "o certificado vence em" in capsys.readouterr().out


def test_baixar_guarda_de_rede_e_excecao_saem_so_com_rotulo(monkeypatch, cofre, pasta, tmp_path, capsys):
    _configurar(monkeypatch, pasta, _pfx(tmp_path))
    monkeypatch.setattr(adn, "contexto_tls", lambda cert: None)

    def explode(ctx, cnpj, nsu):
        raise ConnectionResetError(f"{MARCADOR} {SENHA}")

    monkeypatch.setattr(adn, "obter_pagina", explode)
    assert capturador.baixar(pasta) == 1
    out, err = capsys.readouterr()
    assert "FALHOU (ConnectionResetError)" in out and MARCADOR not in out + err and SENHA not in out + err


# ---------- V3: trava entre processos ----------

_SEGURA = ("import sys, time; sys.path.insert(0, sys.argv[1]); from pathlib import Path;"
           "from engine import rodada; cm = rodada.trava(Path(sys.argv[2])); cm.__enter__();"
           "print('segurando', flush=True); time.sleep(120)")


def _pegar_trava(pasta: Path, tentativas: int = 50) -> bool:
    for _ in range(tentativas):  # Windows solta o lock do processo morto logo depois do kill
        try:
            with rodada.trava(pasta):
                return True
        except rodada.Ocupado:
            time.sleep(0.1)
    return False


def test_trava_dono_vivo_antiga_continua_ocupada_e_dono_morto_solta(monkeypatch, cofre, pasta, tmp_path):
    _configurar(monkeypatch, pasta, _pfx(tmp_path))
    p = subprocess.Popen([sys.executable, "-c", _SEGURA, str(MOTOR), str(pasta)],
                         stdout=subprocess.PIPE, text=True)
    try:
        assert p.stdout.readline().strip() == "segurando"
        sete_horas = time.time() - 7 * 3600
        os.utime(pasta / ".trava", (sete_horas, sete_horas))
        assert capturador.baixar(pasta) == 3
    finally:
        p.kill()
        p.wait()
    assert _pegar_trava(pasta)


def test_configurar_com_a_pasta_travada_sai_com_3_e_depois_fica_coerente(monkeypatch, cofre, pasta, tmp_path):
    """Gate 1B, passe 2: dois configurar na mesma pasta nao cruzam cadastro nem senha."""
    assert _configurar(monkeypatch, pasta, _pfx(tmp_path)) == 0
    antes = (pasta / "capturador.json").read_bytes()
    arq_b = _pfx(tmp_path, CNPJ_B)
    p = subprocess.Popen([sys.executable, "-c", _SEGURA, str(MOTOR), str(pasta)],
                         stdout=subprocess.PIPE, text=True)
    try:
        assert p.stdout.readline().strip() == "segurando"
        assert _configurar(monkeypatch, pasta, arq_b, cnpj=CNPJ_B) == 3
        assert (pasta / "capturador.json").read_bytes() == antes
        assert ("capturador-de-notas", CNPJ_B) not in cofre.dados
    finally:
        p.kill()
        p.wait()
    assert _pegar_trava(pasta)
    assert _configurar(monkeypatch, pasta, arq_b, cnpj=CNPJ_B) == 0
    cfg = json.loads((pasta / "capturador.json").read_text(encoding="utf-8"))
    assert sorted(e["cnpj"] for e in cfg["empresas"]) == sorted([CNPJ_A, CNPJ_B])
    assert set(cofre.dados) == {("capturador-de-notas", CNPJ_A), ("capturador-de-notas", CNPJ_B)}
    assert not list(pasta.glob("*.tmp"))


# ---------- agendar ----------

def test_agendar_windows_chama_schtasks_sem_segredo(monkeypatch, cofre, pasta, tmp_path, capsys):
    _configurar(monkeypatch, pasta, _pfx(tmp_path))
    vistos = []
    monkeypatch.setattr(capturador, "os", types.SimpleNamespace(name="nt"))
    monkeypatch.setattr(capturador.subprocess, "run",
                        lambda args, **k: vistos.append(args) or types.SimpleNamespace(returncode=0))
    assert capturador.agendar(pasta, "06:30") == 0
    args = vistos[0]
    assert args[:2] == ["schtasks", "/Create"] and args[args.index("/TN") + 1] == capturador._nome_tarefa(pasta.resolve())
    assert args[args.index("/ST") + 1] == "06:30" and f'--pasta "{pasta.resolve()}"' in args[-1]
    assert SENHA not in " ".join(args)


@pytest.mark.skipif(os.name != "nt", reason="so a raiz do Windows termina em barra invertida")
def test_agendar_windows_raiz_do_disco_dobra_a_barra_final(monkeypatch):
    """Na raiz (D:), a barra final dobrada chega inteira ao argv da tarefa; sozinha, escaparia a aspa."""
    vistos = []
    monkeypatch.setattr(capturador, "_ler_config", lambda p: {"empresas": []})
    monkeypatch.setattr(capturador, "os", types.SimpleNamespace(name="nt"))
    monkeypatch.setattr(capturador.subprocess, "run",
                        lambda args, **k: vistos.append(args) or types.SimpleNamespace(returncode=0))
    raiz = Path(Path.cwd().anchor)
    assert capturador.agendar(raiz, "06:00") == 0
    assert vistos[0][-1].endswith(f'--pasta "{raiz}\\"')
    assert vistos[0][vistos[0].index("/TN") + 1] == capturador._nome_tarefa(raiz)


def test_agendar_fora_do_windows_imprime_o_cron(monkeypatch, cofre, pasta, tmp_path, capsys):
    _configurar(monkeypatch, pasta, _pfx(tmp_path))
    capsys.readouterr()
    monkeypatch.setattr(capturador, "os", types.SimpleNamespace(name="posix"))
    assert capturador.agendar(pasta, "06:05") == 0
    assert capsys.readouterr().out.splitlines()[-1].startswith("5 6 * * * ")


@pytest.mark.parametrize("hora", ["6:00", "24:00", "06:60", "x"])
def test_agendar_hora_invalida_sai_com_2(monkeypatch, cofre, pasta, tmp_path, hora):
    _configurar(monkeypatch, pasta, _pfx(tmp_path))
    assert capturador.agendar(pasta, hora) == 2


def test_ponto_de_entrada_real_de_outra_pasta_de_trabalho(pasta, tmp_path):
    outra = tmp_path / "outra"
    outra.mkdir()
    r = subprocess.run([sys.executable, str(MOTOR / "capturador.py"), "baixar", "--pasta", str(pasta)],
                       capture_output=True, text=True, cwd=outra)
    assert r.returncode == 2 and "rode configurar" in r.stderr


def test_agendar_windows_nome_da_tarefa_e_por_pasta(monkeypatch, cofre, tmp_path):
    pfx_ = _pfx(tmp_path)
    for nome in ("p1", "p2"):
        (tmp_path / nome).mkdir()
        _configurar(monkeypatch, tmp_path / nome, pfx_)  # antes de trocar o os: configurar usa os.replace
    vistos = []
    monkeypatch.setattr(capturador, "os", types.SimpleNamespace(name="nt"))
    monkeypatch.setattr(capturador.subprocess, "run",
                        lambda args, **k: vistos.append(args) or types.SimpleNamespace(returncode=0))
    for nome in ("p1", "p2", "p1"):
        assert capturador.agendar(tmp_path / nome, "06:30") == 0
    nomes = [a[a.index("/TN") + 1] for a in vistos]
    assert nomes[0] != nomes[1] and nomes[0] == nomes[2]
