# HIKScript

[English](#hikscript-en)

Script escrito en Python para detectar y explotar la vulnerabilidad [ICSA-17-124-01](https://us-cert.cisa.gov/ics/advisories/ICSA-17-124-01), también conocida como Hikvision Camera Backdoor.

## Requisitos

Se requieren los paquetes de **shodan** y **Pillow** para funcionar

```
pip3 install shodan Pillow
```

Si después de instalarlos hay errores de **TKinter**, hay que instalar las librerías desde el gestor de paquetes de la distribución.

Distribuciones con **apt**

```
sudo apt install python3-pil python3-tk python3-pil.imagetk
```

Distribuciones con **dnf**

```
sudo dnf install python3-pillow python3-tkinter python3-pillow-tk
```

---

# HIKScript (EN)

Script written in Python to detect and exploit the [ICSA-17-124-01](https://us-cert.cisa.gov/ics/advisories/ICSA-17-124-01) vulnerability, also known as Hikvision Camera Backdoor.

## Requeriments

The **shodan** and **Pillow** packages are required to operate.

```
pip3 install shodan Pillow
```

Si después de instalarlos hay errores de **TKinter**, hay que instalar las librerías desde el gestor de paquetes de la distribución.
If after installation there are **TKinter** errors, the libraries must be installed from the distribution's package manager.

**apt** based distributions.

```
sudo apt install python3-pil python3-tk python3-pil.imagetk
```

**dnf** based distributions.

```
sudo dnf install python3-pillow python3-tkinter python3-pillow-tk
```
