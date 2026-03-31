from fpdf import FPDF
from datetime import datetime  
from pathlib import Path

def separador(pdf, altura=0.3, sombra=0.2):
    """
    Dibuja un separador gris sutil con relieve en la posición actual del PDF.
    pdf: objeto FPDF
    altura: grosor de la barra superior clara
    sombra: grosor de la sombra inferior más oscura

    """
    x_margen = pdf.l_margin
    ancho = pdf.w - 2 * x_margen
    y_actual = pdf.get_y()
    
    # Barra gris clara
    pdf.set_fill_color(200, 200, 200)
    pdf.rect(x=x_margen, y=y_actual, w=ancho, h=altura, style='F')
    
    # Sombra gris más oscura debajo
    pdf.set_fill_color(170, 170, 170)
    pdf.rect(x=x_margen, y=y_actual + altura, w=ancho, h=sombra, style='F')
    
    # Espacio debajo del separador
    pdf.ln(altura + sombra + 2)


def generar_pdf(dominio: str, informe: list[dict], riesgo_final: str, nombre_del_archivo: str = "informe" ):
  
    BASE_DIREC = Path(__file__).resolve().parent 
    IMAGES_DIREC = BASE_DIREC / "Imagenes"
    IMAGEN_RIESGO = {
        "BAJO": IMAGES_DIREC / "indicador_bajo.png",
        "MEDIO": IMAGES_DIREC / "indicador_medio.png",
        "ALTO": IMAGES_DIREC / "indicador_alto.png",
        "CRITICO": IMAGES_DIREC  /"indicador_critico.png"
    }
    LOGO_TSS = IMAGES_DIREC / "logo_tss.jpg"

    INFORMES_DIREC= BASE_DIREC / "Informes Generados"
    INFORMES_DIREC.mkdir(exist_ok=True)
    archivo_pdf= str(INFORMES_DIREC / f"{nombre_del_archivo}.pdf")
    imagen=IMAGEN_RIESGO[riesgo_final]
    if not imagen.exists():
        raise FileNotFoundError(f"No se encontró la imagen: {imagen}")
    if not LOGO_TSS.exists():
        raise FileNotFoundError(f"No se encontro el logo: {LOGO_TSS}")
    
    pdf = FPDF()
    pdf.add_page()
    
    #_____ LOGO _________________________________________________
    pdf.image(str(LOGO_TSS), x=10, w=40)
    pdf.ln(5)

    #_____ TÍTULO ______________________________________________
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "Informe de Superficie de Ataque", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)
    
    pdf.set_font("Helvetica", size=11)
    pdf.multi_cell(
        0, 7,
        "Este informe recoge información pública expuesta por el dominio analizado. "
        "El objetivo es identificar posibles riesgos de configuración relacionados con "
        "la infraestructura web, el correo electrónico y la gestión del dominio."
    )
    pdf.ln(2)

    separador(pdf)

    #_____ INFORMACIÓN GENERAL __________________________________
    #ancho_disponible = pdf.w - 2 * pdf.l_margin
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(0, 7, f"Dominio analizado: {dominio}")

    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(0, 7, f"Fecha del análisis: {datetime.now().strftime('%d/%m/%Y %H:%M')}")

    #_____ Indicador_en_barra __________________________________
    ancho_barra=100
    x_centrado=(pdf.w - ancho_barra) / 2

    pdf.set_font("Arial", "B", 16)
    pdf.set_x(0)  # aseguramos que empieza desde el borde izquierdo
    pdf.cell(pdf.w, 10, "Estado de Riesgo de Seguridad Actual", ln=True, align="C")
    pdf.ln(5)

    pdf.image(imagen, x=x_centrado, w=ancho_barra, h=0 )
    pdf.ln(6)

    #____ RESULTADOS _____________________________________________
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, "Resumen de hallazgos", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)
    """coloca por seccion la lista del informe que se agrupo anteriormente"""
    for seccion in informe:
        pdf.set_font("Times", "B", 14)
        pdf.cell(0, 10, f"-{seccion['categoria']}", new_x="LMARGIN", new_y="NEXT")
        
        separador(pdf)

        pdf.set_font("Helvetica", size=11)
        pdf.cell(0, 7, f"Estado: {seccion['estado']}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 7, f"Nivel de riesgo: {seccion['riesgo']}", new_x="LMARGIN", new_y="NEXT")
        pdf.multi_cell(0, 7, f"Descripción: {seccion['descripcion']}")

        separador(pdf) 

        pdf.ln(4)
       
    pdf.cell(0, 5, "Limitaciones del análisis", new_x="LMARGIN", new_y="NEXT")
    
    pdf.set_font("Helvetica", size=7)
    pdf.multi_cell(
        0, 5,
        "La detección de infraestructura y CDN se basa en técnicas que contemplan\n"
        "un conjunto limitado de rangos IP y proveedores conocidos.\n"
        "Esta identificación no representa una clasificación exhaustiva de todos los posibles proveedores\n" 
        "de infraestructura o mecanismos de protección existentes."
        )
    pdf.ln(6)
    
    pdf.output(archivo_pdf)
    return archivo_pdf 