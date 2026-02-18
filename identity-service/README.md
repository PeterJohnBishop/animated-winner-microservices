# identity-service

http://identity-service

POST /new

{
    "name": "test1",
    "email": "test1@example.com",
    "password": "password123"
}

POST /login

{
    "email": "test1@example.com",
    "password": "password123"
}

GET /auth/users

GET /auth/users/:id

PUT /auth/users

{
    "id": "id_4LM0hbZB",
    "name": "John Doe",
    "email": "john.doe@example.com"
}

PUT /auth/users/password

{
            "id": "id_4LM0hbZB",
            "currentPassword": "123password",
            "newPassword": "password123"
}

DELETE /auth/users/:id

REFRESH /auth/refresh