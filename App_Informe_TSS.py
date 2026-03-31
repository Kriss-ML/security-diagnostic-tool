import TSS_diagnostico_seguridad as ds 
import pandas as pd 
from datetime import datetime
import sys
import generar_pdf as gpdf 
import numpy as np
import os 

def generar_dominio_aleatorio():
    dominios=["google.com","example.com", "powerdmarc.com"]
    dominio = str(np.random.choice(dominios).lower())
    nombre = str(dominio.split(".")[0])
    generar_informe_cliente(dominio=dominio, nombre_cliente=nombre)        


def riesgo_general(puntaje: int) -> str:
    
    if puntaje <= 100:
        return "BAJO"
    elif puntaje <= 180:
        return "MEDIO"
    elif puntaje <= 230:
        return "ALTO"
    else:
        return "CRITICO"    

def generar_informe_cliente(nombre_cliente, dominio):
    informe_seguridad = ds.diagnostico_Seguridad(dominio)
    informe_df = pd.DataFrame(informe_seguridad)
    mensaje=f"Vista previa: Informe de seguridad del domonio: {dominio}"
    print("-" * len(mensaje))
    print(mensaje)
    print("-" * len(mensaje))
    descripcion = informe_df["descripcion"]
    informe_df_pantalla = informe_df.drop("descripcion", axis=1)
    puntaje_final = informe_df['puntaje'].sum()
    riesgo_final=riesgo_general(puntaje_final)
    print(informe_df_pantalla)
    print(f"Puntaje de Riesgo Total: {puntaje_final}")
    print(f"Riesgo final del diagnostico: {riesgo_final}")
    print("-----------------------------------------------------------")
    informe_df=informe_df.drop("puntaje", axis=1)
    informe_df["Detalles"]= descripcion
    informe_lista=informe_df.to_dict(orient="records")
    ruta = gpdf.generar_pdf(dominio=dominio, informe=informe_lista, nombre_del_archivo=nombre_cliente, riesgo_final=riesgo_final)  
    input("Presione ENTER para visualizar el informe en PDF")
    os.startfile(ruta)
      
def menu():
    while True:
        print("--------------------------------")
        print("-------TSS-CiberSeguridad-------")
        print("--------------------------------")
        try:
            respuesta = int(input("1.Generar Informe Cliente\n2.(Test): Generar informe de un dominio aleatorio(1/3)\n3.Salir\n(1/3):"))
        except ValueError:
            print("Comando Desconocido...")
            continue    
        if respuesta == 1:
            nombre_cliente = input("Ingrese el Nombre del Cliente: ").strip()
            dominio = input("Ingrese el Dominio  del Cliente: ").strip()
            if nombre_cliente == "" or dominio =="":
                print("------------------------------------------------------")
                print("Error [Nombre] o [Dominio] vacio. Intentelo Nuevamente")
                print("------------------------------------------------------")
                continue 
            try:
                generar_informe_cliente(nombre_cliente, dominio)
            except ValueError as e:
                mensaje_error = "Dominio invalido. Intentelo Nuevamente...."
                print("-"*len(mensaje_error))
                print(f"Error: {e}")
                print(mensaje_error)    
                print("-"*len(mensaje_error))
                
        elif respuesta== 2:
            generar_dominio_aleatorio()
        
        elif respuesta == 3:
            sys.exit("Saliendo.....")
        else:
            print("Numero Fuera de rango Intente Nuevamente...")
            continue

if __name__=="__main__":
    menu()
 