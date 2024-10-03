Violaciones a las convenciones de codificación del lenguaje de programación escogido.

a. JavaScript (Clase Carrito y Archivos Relacionados js)
Duplicación de la Clase Carrito. Se observa que la clase Carrito está definida dos veces en el primer fragmento de código proporcionado. Esto puede causar conflictos y comportamientos inesperados.
Nomenclatura Inconsistente. Algunas variables y métodos utilizan nombres en español mientras que otros pueden mezclarse con inglés o no seguir una convención clara.
Bugs y Vulnerabilidades:
Reasignación Incorrecta de Variables: En el método leerDatosProducto, productosLS se reasigna a un valor individual (productoLS.id), lo que podría causar errores en lógica posterior que espera un array.
Falta de Manejo de Errores: Muchos métodos carecen de manejo de errores robusto, lo que puede llevar a fallos silenciosos.

b. PHP (Archivos login.php y adoptar.php)
Inyección de Código HTML en PHP: Se utiliza echo para insertar grandes bloques de HTML, lo que puede dificultar la lectura y mantenimiento.
Inconsistencia en el Uso de Comillas: Se alternan comillas simples y dobles de manera inconsistente, lo que puede afectar la legibilidad.





Violaciones a las prácticas Clean Code.
JavaScript (Clase Carrito y Archivos Relacionados)
Métodos Largos y Monolíticos: Algunos métodos, como validarFormulario y leerDatosProducto, realizan múltiples tareas, violando el principio de Single Responsibility.
Falta de Modularidad: El código tiene funciones que podrían estar mejor organizadas en módulos separados para mejorar la legibilidad y mantenibilidad.
Nombres Poco Descriptivos: Aunque los nombres están en español, podrían ser más descriptivos para facilitar la comprensión.

PHP (Archivos login.php y adoptar.php)
SQL Injection Vulnerabilidad: El código utiliza concatenación de cadenas para construir consultas SQL, lo que es vulnerable a inyecciones SQL.
Almacenamiento de Contraseñas en Texto Plano: Las contraseñas se almacenan directamente en la base de datos sin hashing, lo que es una grave vulnerabilidad de seguridad.
Mezcla de Lógica y Presentación: La lógica de negocio (verificación de usuario) está mezclada con la presentación (HTML), lo que viola el principio de Separation of Concerns.

Bugs, code smells y vulnerabilities 
a. JavaScript (Clase Carrito y Archivos Relacionados)
Reasignación Incorrecta de Variables: En el método leerDatosProducto, productosLS se reasigna a un valor individual (productoLS.id), lo que podría causar errores en lógica posterior que espera un array.
Falta de Manejo de Errores: Muchos métodos carecen de manejo de errores robusto, lo que puede llevar a fallos silenciosos.
b. PHP (Archivos login.php y adoptar.php)
SQL Injection: Uso de variables sin sanitizar en consultas SQL.
Almacenamiento de Contraseñas en Texto Plano: Facilita el acceso no autorizado en caso de brechas de seguridad.
Falta de Validación Adecuada en el Lado del Servidor: Aunque hay validación en el formulario, la validación del lado del servidor es insuficiente.
Correcciones y Refactorizaciones Implementadas
a. Corrección de Vulnerabilidad de SQL Injection en login.php
Violación:
SQL Injection Vulnerabilidad: El uso de concatenación directa de variables en consultas SQL permite a un atacante inyectar código SQL malicioso.
Corrección/Refactorización:
Uso de Sentencias Preparadas con mysqli: Implementar consultas preparadas para evitar la inyección de SQL y asegurar que los datos ingresados por el usuario se traten como parámetros, no como parte de la consulta.

- Fragmento de Código Original:
$query=mysqli_query($con, "SELECT * FROM usuario WHERE correo='".$usuario."' AND password='".$pass."'");

- Fragmento de Código Corregido:
// Preparar la declaración
$stmt = $con->prepare("SELECT * FROM usuario WHERE correo = ? AND password = ?");
$stmt->bind_param("ss", $usuario, $pass);

// Ejecutar la declaración
$stmt->execute();

// Obtener el resultado
$result = $stmt->get_result();
$numrows = $result->num_rows;

if($numrows != 0) {
    while($row = $result->fetch_assoc()) {
        $dbusername = $row['correo'];
        $dbpassword = $row['password'];
        $dbnombre = $row['nombre'];
    }
    
    if($usuario == $dbusername && $pass == $dbpassword) {
        session_start();
        $_SESSION['sess_user'] = $dbnombre;
        header("Location: home.php");
    }  
} else {
    $message = "Error! Usuario o password inválidos";
    echo "<script type='text/javascript'>alert('$message');</script>";
}

b. Implementación de Hashing de Contraseñas en login.php
Violación:
Almacenamiento de Contraseñas en Texto Plano: Las contraseñas se almacenan sin cifrar, lo que representa una vulnerabilidad grave en caso de acceso no autorizado a la base de datos.
Corrección/Refactorización:
Uso de password_hash y password_verify: Implementar funciones de hashing para almacenar contraseñas de forma segura y verificar contraseñas durante el inicio de sesión.
- Fragmento de Código Original (Parte del Registro):
// Asumiendo que durante el registro, las contraseñas se almacenan directamente
$pass=$_POST['password'];
// Insertar en la base de datos sin hashing

- Fragmento de Código Corregido (Registro):
// Hash de la contraseña antes de almacenarla
$pass = password_hash($_POST['password'], PASSWORD_BCRYPT);

// Preparar la declaración para insertar el usuario
$stmt = $con->prepare("INSERT INTO usuario (correo, password, nombre) VALUES (?, ?, ?)");
$stmt->bind_param("sss", $usuario, $pass, $nombre);

// Ejecutar la declaración
$stmt->execute();

- Fragmento de Código Corregido (Inicio de Sesión):
php
Copiar código
// Consulta para obtener el usuario por correo
$stmt = $con->prepare("SELECT * FROM usuario WHERE correo = ?");
$stmt->bind_param("s", $usuario);
$stmt->execute();
$result = $stmt->get_result();

if($result->num_rows != 0) {
    $row = $result->fetch_assoc();
    $dbusername = $row['correo'];
    $dbpassword = $row['password']; // Hashed password
    $dbnombre = $row['nombre'];
    
    // Verificar la contraseña
    if(password_verify($pass, $dbpassword)) {
        session_start();
        $_SESSION['sess_user'] = $dbnombre;
        header("Location: home.php");
    } else {
        $message = "Error! Usuario o password inválidos";
        echo "<script type='text/javascript'>alert('$message');</script>";
    }
} else {
    $message = "Error! Usuario o password inválidos";
    echo "<script type='text/javascript'>alert('$message');</script>";
}

c. Eliminación de Código Duplicado y Mejora de la Clase Carrito en JavaScript

Violación:
Duplicación de la Clase Carrito: La clase Carrito está definida dos veces con métodos que se solapan, lo que puede llevar a comportamientos inesperados y dificultades de mantenimiento.
Corrección/Refactorización:
Consolidación de la Clase Carrito: Fusionar ambas definiciones de la clase Carrito en una sola, asegurando que cada método sea único y eliminando redundancias.
Refactorización de Métodos para Reducir Complejidad: Dividir métodos largos en funciones más pequeñas y enfocadas, mejorar la legibilidad y mantenibilidad.

- Fragmento de Código Original (Clase Carrito):
class Carrito {
    // Primer conjunto de métodos...
}

class Carrito {
    // Segundo conjunto de métodos...
}

- Fragmento de Código Corregido (Clase Carrito)
class Carrito {
    // Conjunto de total de métodos...
}

- Explicación:
Eliminación de Duplicación: Se consolidaron ambas definiciones de la clase Carrito en una sola, eliminando redundancias y posibles conflictos.
Uso de Métodos Modernos: Se utilizaron métodos como closest para una selección más robusta de elementos en el DOM.
Reducción de Complejidad: Métodos largos se dividieron en funciones más pequeñas y enfocadas, como validarCampos, actualizarContador, etc.
Uso de const y let: Asegura la correcta declaración de variables, evitando reasignaciones innecesarias.


Reporte Sonarlint de análisis estático.

Remove this useless assignment to variable "subtotal".
Expected a `for-of` loop instead of a `for` loop with this simple iteration.
Refactor this function to not always return the same value. [+2 locations]
Unexpected var, use let or const instead.
Unnecessary escape character: \_.
Unnecessary escape character: \..
Unnecessary escape character: \-.
Unnecessary escape character: \#.
Unnecessary escape character: \/.
