"""V2 e V3 (idempotencia): rodada sobre o ADN falso, sem rede."""
from __future__ import annotations

import csv
import json
import shutil
import sqlite3

import pytest

from engine import base, rodada
from engine.adn import Pagina
from tests.sinteticos import (CNPJ_A, CNPJ_B, MARCADOR, ADNFalso, envelope, evento_xml, ilegivel,
                              nfse_xml)


def _con(tmp_path):
    return base.abrir(tmp_path / "base.sqlite")


def _historico(n: int, cnpj_toma: str = CNPJ_A) -> list:
    return [envelope(i, nfse_xml(i, toma=cnpj_toma, aliquota=i % 2 == 0)) for i in range(1, n + 1)]


def test_primeira_rodada_traz_o_historico_em_paginas_de_50(tmp_path):
    adn = ADNFalso({CNPJ_A: _historico(87)})
    con = _con(tmp_path)
    c = rodada.rodar_empresa(con, tmp_path, CNPJ_A, adn)
    assert (c.notas_novas, c.paginas, c.parada) == (87, 2, "fim")
    assert c.papeis == {"emitida": 0, "recebida": 87, "intermediario": 0, "outro": 0}
    assert adn.chamadas == [(CNPJ_A, 0), (CNPJ_A, 50)]  # lote de 37 < 50: para sem 3a chamada
    assert base.ler_cursor(con, CNPJ_A) == 87
    assert len(list((tmp_path / CNPJ_A / "2026-03").glob("*.xml"))) == 87


def test_lote_de_exatamente_50_pede_a_proxima(tmp_path):
    adn = ADNFalso({CNPJ_A: _historico(50)})
    c = rodada.rodar_empresa(_con(tmp_path), tmp_path, CNPJ_A, adn)
    assert (c.notas_novas, c.parada) == (50, "fim")
    assert adn.chamadas == [(CNPJ_A, 0), (CNPJ_A, 50)]  # a 2a volta 404


def test_segunda_rodada_sem_nota_nova_faz_uma_chamada_e_zero_insercoes(tmp_path):
    con = _con(tmp_path)
    rodada.rodar_empresa(con, tmp_path, CNPJ_A, ADNFalso({CNPJ_A: _historico(87)}))
    adn = ADNFalso({CNPJ_A: _historico(87)})
    c = rodada.rodar_empresa(con, tmp_path, CNPJ_A, adn)
    assert (c.notas_novas, len(adn.chamadas), c.parada) == (0, 1, "fim")


def test_campo_ausente_fica_null_nunca_zero(tmp_path):
    con = _con(tmp_path)
    rodada.rodar_empresa(con, tmp_path, CNPJ_A, ADNFalso({CNPJ_A: _historico(2)}))
    linhas = dict(con.execute("SELECT nsu, iss_aliquota FROM notas").fetchall())
    assert linhas == {1: None, 2: "2.00"}


def test_429_e_teto_encerram_sem_falhar_e_guardam_o_cursor(tmp_path):
    con = _con(tmp_path)
    adn = ADNFalso({CNPJ_A: _historico(120)}, roteiro={1: Pagina(429, [])})
    c = rodada.rodar_empresa(con, tmp_path, CNPJ_A, adn)
    assert (c.parada, base.ler_cursor(con, CNPJ_A), rodada.falhou(c)) == ("429", 50, False)
    c = rodada.rodar_empresa(con, tmp_path, CNPJ_A, ADNFalso({CNPJ_A: _historico(120)}), teto=1)
    assert (c.parada, base.ler_cursor(con, CNPJ_A), rodada.falhou(c)) == ("teto", 100, False)


@pytest.mark.parametrize("status", [400, 403, 500])
def test_status_inesperado_falha_a_empresa_sem_andar_o_cursor(tmp_path, status):
    con = _con(tmp_path)
    c = rodada.rodar_empresa(con, tmp_path, CNPJ_A, ADNFalso({}, roteiro={0: Pagina(status, [])}))
    assert (c.parada, rodada.falhou(c), base.ler_cursor(con, CNPJ_A)) == (f"http-{status}", True, 0)


@pytest.mark.parametrize("pagina", [Pagina(200, []), Pagina(404, [])])
def test_lote_vazio_e_404_valem_sem_nota_nova(tmp_path, pagina):
    c = rodada.rodar_empresa(_con(tmp_path), tmp_path, CNPJ_A, ADNFalso({}, roteiro={0: pagina}))
    assert (c.notas_novas, c.parada, rodada.falhou(c)) == (0, "fim", False)


def test_itens_fora_de_ordem_e_cursor_no_maior_nsu(tmp_path):
    con = _con(tmp_path)
    itens = list(reversed(_historico(3)))
    rodada.rodar_empresa(con, tmp_path, CNPJ_A, ADNFalso({}, roteiro={0: Pagina(200, itens)}))
    assert base.ler_cursor(con, CNPJ_A) == 3


def test_nsu_maior_que_o_inteiro_do_sqlite_para_a_pagina_sem_estourar(tmp_path):
    con = _con(tmp_path)
    item = dict(_historico(1)[0], NSU=10**19)
    c = rodada.rodar_empresa(con, tmp_path, CNPJ_A, ADNFalso({}, roteiro={0: Pagina(200, [item])}))
    assert (c.parada, rodada.falhou(c), base.ler_cursor(con, CNPJ_A)) == ("resposta-fora-do-formato", True, 0)


def test_mesma_nota_em_duas_empresas_mantem_as_duas_linhas_papeis_e_cursores(tmp_path):
    con = _con(tmp_path)
    nota = nfse_xml(7, prest=CNPJ_B, toma=CNPJ_A)
    adn = ADNFalso({CNPJ_A: [envelope(5, nota)], CNPJ_B: [envelope(9, nota)]})
    rodada.rodar_empresa(con, tmp_path, CNPJ_A, adn)
    rodada.rodar_empresa(con, tmp_path, CNPJ_B, adn)
    linhas = sorted(con.execute("SELECT cnpj_empresa, papel, nsu FROM notas").fetchall())
    assert linhas == [(CNPJ_A, "recebida", 5), (CNPJ_B, "emitida", 9)]
    assert (base.ler_cursor(con, CNPJ_A), base.ler_cursor(con, CNPJ_B)) == (5, 9)


def test_evento_de_cancelamento_antes_e_depois_da_nota(tmp_path):
    con = _con(tmp_path)
    # evento chega antes (NSU 1) da nota 2 e depois (NSU 4) da nota 3; codigo 202201 so registra
    itens = [envelope(1, evento_xml(2), "EVENTO"), envelope(2, nfse_xml(2)), envelope(3, nfse_xml(3)),
             envelope(4, evento_xml(3, "105104"), "EVENTO"), envelope(5, nfse_xml(5)),
             envelope(6, evento_xml(5, "202201"), "EVENTO")]
    c = rodada.rodar_empresa(con, tmp_path, CNPJ_A, ADNFalso({CNPJ_A: itens}))
    assert c.eventos == 3
    sit = dict(con.execute("SELECT nsu, situacao FROM notas").fetchall())
    assert sit == {2: "cancelada", 3: "cancelada", 5: "normal"}


def test_tipo_desconhecido_conta_como_outro(tmp_path):
    c = rodada.rodar_empresa(_con(tmp_path), tmp_path, CNPJ_A,
                             ADNFalso({CNPJ_A: [envelope(1, b"<x/>", "CTE")]}))
    assert (c.outros, c.notas_novas) == (1, 0)


def test_item_ilegivel_vira_pendencia_sem_perda_e_e_reprocessado(tmp_path, monkeypatch):
    con = _con(tmp_path)
    itens = _historico(50)
    itens[19] = envelope(20, b"<NFSe><quebrado")  # XML invalido no item 20
    itens.append(ilegivel(51))                     # gzip invalido no item 51
    c = rodada.rodar_empresa(con, tmp_path, CNPJ_A, ADNFalso({CNPJ_A: itens}))
    assert (c.notas_novas, c.pendentes_novas, base.ler_cursor(con, CNPJ_A)) == (49, 2, 51)
    pend = dict(con.execute("SELECT nsu, etapa FROM pendencias").fetchall())
    assert pend == {20: "xml", 51: "gzip"}
    assert (tmp_path / CNPJ_A / "pendentes" / "20.json").exists()
    # o "parser corrigido": o envelope em disco passa a ter XML valido
    import json
    arq = tmp_path / CNPJ_A / "pendentes" / "20.json"
    arq.write_text(json.dumps(envelope(20, nfse_xml(20))), encoding="utf-8")
    c = rodada.rodar_empresa(con, tmp_path, CNPJ_A, ADNFalso({CNPJ_A: itens}))
    assert (c.pendentes_resolvidas, c.pendentes_novas, c.pendentes_total) == (1, 0, 1)
    assert con.execute("SELECT COUNT(*) FROM notas WHERE nsu=20").fetchone()[0] == 1
    assert not arq.exists()
    c = rodada.rodar_empresa(con, tmp_path, CNPJ_A, ADNFalso({CNPJ_A: itens}))
    assert (c.pendentes_novas, c.pendentes_total) == (0, 1)  # a 51 segue pendente, sem duplicar


def test_queda_no_meio_da_pagina_repete_sem_duplicar(tmp_path, monkeypatch):
    con = _con(tmp_path)
    original = base.gravar_nota
    chamadas = {"n": 0}

    def cai_na_30a(*a, **k):
        chamadas["n"] += 1
        if chamadas["n"] == 30:
            raise sqlite3.OperationalError("disco cheio simulado")
        return original(*a, **k)

    monkeypatch.setattr(base, "gravar_nota", cai_na_30a)
    with pytest.raises(sqlite3.OperationalError):
        rodada.rodar_empresa(con, tmp_path, CNPJ_A, ADNFalso({CNPJ_A: _historico(60)}))
    assert con.execute("SELECT COUNT(*) FROM notas").fetchone()[0] == 0  # a pagina inteira voltou
    assert base.ler_cursor(con, CNPJ_A) == 0
    monkeypatch.setattr(base, "gravar_nota", original)
    c = rodada.rodar_empresa(con, tmp_path, CNPJ_A, ADNFalso({CNPJ_A: _historico(60)}))
    assert (c.notas_novas, con.execute("SELECT COUNT(*) FROM notas").fetchone()[0]) == (60, 60)


def test_csv_bom_ponto_e_virgula_decimal_com_virgula_e_acento(tmp_path):
    con = _con(tmp_path)
    xml = nfse_xml(1).replace(b"<vLiq>980.00</vLiq>", b"<vLiq>980.50</vLiq>")
    xml = xml.replace("CONTRAPARTE MARCADOR ZQX".encode(), "Serviço de Manutenção".encode("utf-8"))
    rodada.rodar_empresa(con, tmp_path, CNPJ_A, ADNFalso({CNPJ_A: [envelope(1, xml)]}))
    n = base.exportar_csv(con, tmp_path / "notas.csv")
    bruto = (tmp_path / "notas.csv").read_bytes()
    assert n == 1 and bruto.startswith(b"\xef\xbb\xbf")
    linhas = list(csv.DictReader((tmp_path / "notas.csv").open(encoding="utf-8-sig"), delimiter=";"))
    assert linhas[0]["valor_liquido"] == "980,50" and linhas[0]["iss_aliquota"] == "2,00"
    assert linhas[0]["emitente_nome"] == "Serviço de Manutenção"
    assert linhas[0]["papel"] == "recebida" and linhas[0]["chave"].isdigit()


def test_csv_neutraliza_formula_em_texto_do_fornecedor(tmp_path):
    con = _con(tmp_path)
    xml = nfse_xml(1).replace(f"<xDescServ>{MARCADOR}".encode(), b"<xDescServ>=1+1")
    xml = xml.replace(f"<emit><CNPJ>{CNPJ_B}</CNPJ><xNome>{MARCADOR}".encode(),
                      f"<emit><CNPJ>{CNPJ_B}</CNPJ><xNome>@ACME".encode())
    rodada.rodar_empresa(con, tmp_path, CNPJ_A, ADNFalso({CNPJ_A: [envelope(1, xml)]}))
    base.exportar_csv(con, tmp_path / "notas.csv")
    linha = list(csv.DictReader((tmp_path / "notas.csv").open(encoding="utf-8-sig"), delimiter=";"))[0]
    assert linha["discriminacao"] == "'=1+1" and linha["emitente_nome"] == "'@ACME"
    assert linha["valor_liquido"] == "980,00"  # decimal segue sem apostrofo (negativo nao e facil na fixture)


def test_pendencia_sobrevive_a_pasta_movida(tmp_path):
    velha = tmp_path / "velha"
    velha.mkdir()
    con = base.abrir(velha / "base.sqlite")
    itens = [envelope(1, b"<NFSe><quebrado")]
    c = rodada.rodar_empresa(con, velha, CNPJ_A, ADNFalso({CNPJ_A: itens}))
    assert (c.pendentes_novas, c.notas_novas) == (1, 0)
    con.close()
    nova = tmp_path / "nova"
    shutil.move(str(velha), str(nova))
    (nova / CNPJ_A / "pendentes" / "1.json").write_text(
        json.dumps(envelope(1, nfse_xml(1))), encoding="utf-8")  # o "parser corrigido"
    con = base.abrir(nova / "base.sqlite")
    c = rodada.rodar_empresa(con, nova, CNPJ_A, ADNFalso({CNPJ_A: itens}))
    assert (c.pendentes_resolvidas, c.pendentes_total) == (1, 0)
    assert con.execute("SELECT COUNT(*) FROM notas").fetchone()[0] == 1
    assert con.execute("SELECT arquivo FROM notas").fetchone()[0].startswith(CNPJ_A + "/")


def _pendencia_formato_antigo(tmp_path):
    """Pendencia gravada pela versao anterior: coluna `arquivo` com caminho ABSOLUTO na pasta original."""
    velha = tmp_path / "velha"
    velha.mkdir()
    con = base.abrir(velha / "base.sqlite")
    itens = [envelope(1, b"<NFSe><quebrado")]
    rodada.rodar_empresa(con, velha, CNPJ_A, ADNFalso({CNPJ_A: itens}))
    env = velha / CNPJ_A / "pendentes" / "1.json"
    with con:
        con.execute("UPDATE pendencias SET arquivo=?", (str(env),))
    con.close()
    env.write_text(json.dumps(envelope(1, nfse_xml(1))), encoding="utf-8")  # o "parser corrigido"
    return velha, itens


def test_pendencia_formato_antigo_com_pasta_movida_resolve(tmp_path):
    velha, itens = _pendencia_formato_antigo(tmp_path)
    nova = tmp_path / "nova"
    shutil.move(str(velha), str(nova))
    con = base.abrir(nova / "base.sqlite")
    c = rodada.rodar_empresa(con, nova, CNPJ_A, ADNFalso({CNPJ_A: itens}))
    assert (c.pendentes_resolvidas, c.pendentes_total) == (1, 0)
    assert con.execute("SELECT COUNT(*) FROM notas").fetchone()[0] == 1


def test_pendencia_formato_antigo_com_pasta_copiada_so_apaga_o_da_copia(tmp_path):
    velha, itens = _pendencia_formato_antigo(tmp_path)
    original = (velha / CNPJ_A / "pendentes" / "1.json").read_bytes()
    copia = tmp_path / "copia"
    shutil.copytree(velha, copia)
    con = base.abrir(copia / "base.sqlite")
    c = rodada.rodar_empresa(con, copia, CNPJ_A, ADNFalso({CNPJ_A: itens}))
    assert (c.pendentes_resolvidas, c.pendentes_total) == (1, 0)
    assert con.execute("SELECT COUNT(*) FROM notas").fetchone()[0] == 1
    assert not (copia / CNPJ_A / "pendentes" / "1.json").exists()
    assert (velha / CNPJ_A / "pendentes" / "1.json").read_bytes() == original


def test_pasta_com_espaco(tmp_path):
    pasta = tmp_path / "Douglas Ferreira" / "notas fiscais"
    pasta.mkdir(parents=True)
    c = rodada.rodar_empresa(base.abrir(pasta / "base.sqlite"), pasta, CNPJ_A,
                             ADNFalso({CNPJ_A: _historico(3)}))
    assert c.notas_novas == 3
