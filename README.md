# Boilerplate code para Refresh tokens

---

## Spike JWT para Refresh Tokens

Este repositorio contiene un boilerplate de Node.js diseñado para implementar un sistema de autenticación robusto y seguro utilizando **JSON Web Tokens (JWT)** para `access tokens` y un mecanismo de `refresh tokens` para la gestión de sesiones y la renovación de tokens. Está configurado para trabajar con **MongoDB** como base de datos.

---

## Endpoints de la API

  * **`POST /api/auth/register`**: Registra un nuevo usuario.
  * **`POST /api/auth/login`**: Inicia sesión y obtiene un `access token` y establece una `refresh token` como `HttpOnly cookie`.
  * **`POST /api/auth/refresh`**: Utiliza el `refresh token` de la cookie para obtener un nuevo `access token`.
  * **`GET /api/auth/logout`**: Cierra la sesión del usuario, invalidando el `refresh token` y el `access token`.
  * **`GET /api/auth/profile`**: Ruta protegida de ejemplo. Requiere un `access token` válido.
