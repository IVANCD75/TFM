import sys
from streamlit.web import cli as stcli
from utils import resolve_path

if __name__ == "__main__":
    script_path = resolve_path("dashboard_tfm.py")

    sys.argv = [
        "streamlit",
        "run",
        script_path,
        "--global.developmentMode=false",
        "--server.address=localhost", # Para que solo sea accesible en la máquina host no desde ningún lado, mediante IP pública
    ]

    sys.exit(stcli.main())