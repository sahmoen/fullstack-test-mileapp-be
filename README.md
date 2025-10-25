# MileApp — Backend

> Backend service built with Node.js + Express for the MileApp Task Management project.

## 🚀 Getting Started

### 1. Installation
```bash
cd backend
npm install
```

### 2. Running
Development mode:
```bash
npm run dev
```
Production mode:
```bash
npm start
```

### 3. Environment Variables (.env)
```
PORT=5000
MONGO_URI=mongodb://localhost:27017/mileapp
JWT_SECRET=your_jwt_secret
JWT_EXPIRES_IN=1d
NODE_ENV=development
```

---

## 📡 API Endpoints

### AUTH ROUTES
#### **POST /login/register**
Create a new user.

**Request:**
```json
{
  "username": "johndoe",
  "email": "john@example.com",
  "password": "password123",
  "role": "user"
}
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "_id": "64fa...",
    "username": "johndoe",
    "email": "john@example.com",
    "role": "user"
  }
}
```

#### **POST /login/login**
Authenticate user and return JWT token.

**Request:**
```json
{
  "identifier": "john@example.com",
  "password": "password123"
}
```

**Response:**
```json
{
  "token": "eyJhbGci...",
  "role": "user"
}
```

#### **POST /login/forgot-password**
Send reset token to email.

**Request:**
```json
{ "email": "john@example.com" }
```

#### **GET /login/verify-reset-token/:token**
Verify password reset token.

#### **POST /login/reset-password**
Reset password using token.

**Request:**
```json
{
  "token": "<token>",
  "password": "newpassword123"
}
```

---

### TASK ROUTES (Protected)
Use `Authorization: Bearer <token>`

#### **GET /tasks**
Get all tasks with pagination, filtering, and sorting.

Query example:
`/tasks?page=1&limit=10&sort=-createdAt&search=meeting&status=done`

#### **POST /tasks**
Create new task.

#### **PUT /tasks/:id**
Update existing task.

#### **DELETE /tasks/:id**
Delete task by ID.

---

## 🧠 Why These Database Indexes

1. `{ user: 1 }` → To quickly fetch user-specific tasks.
2. `{ createdAt: -1 }` → Optimized sorting by latest tasks.
3. `{ title: "text", description: "text" }` → For text-based search (using `$regex` or full-text).
4. `{ user: 1, createdAt: -1 }` → Compound index improves pagination query performance.

These indexes help achieve **faster query times**, especially under pagination + filters, while keeping MongoDB storage cost minimal.

---

## 🔐 Security Highlights

- JWT-based authentication
- Password hashing with bcrypt
- Joi validation on all inputs
- Role-based route authorization
- Error-handling middleware
- CORS protection
- Prevents mass assignment by schema validation

---

## ⚙️ Stability & Scalability

- Modular controller + route structure
- Centralized error handler
- Mongoose schema validation
- Indexed queries improve scalability
- Clear separation of Auth & Task logic
