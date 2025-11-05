# Backend - Simple Express API

Sebuah backend sederhana menggunakan Express.js yang menyediakan otentikasi (registrasi & login) dan operasi CRUD untuk `items` (dengan proteksi JWT).

## Ringkasan

- Bahasa: JavaScript (Node.js)
- Framework: Express
- Fitur utama:
	- Registrasi pengguna (hash password dengan bcryptjs)
	- Login (menghasilkan token JWT)
	- Middleware verifikasi token (untuk proteksi route)
	- CRUD sederhana untuk `items` (in-memory)

> Catatan: Data disimpan di memori (variabel runtime). Untuk penggunaan nyata, hubungkan ke database (MongoDB, PostgreSQL, dsb.).

## Prerequisites

- Node.js (disarankan v14+)
- npm (disertakan bersama Node.js)

## Instalasi

1. Clone repository atau salin file ke folder kerja.
2. Install dependency:

```powershell
npm install
```

## Menjalankan server

Cara paling mudah menjalankan server:

```powershell
node server.js
```

Atau gunakan skrip npm (jika sudah ada):

```powershell
npm start
```

Server akan berjalan pada http://localhost:5000

## Konfigurasi

Saat ini secret JWT berada langsung di `server.js` sebagai `SECRET_KEY`. Ganti dengan variabel lingkungan untuk produksi. Contoh nilai default di kode:

```
const SECRET_KEY = 'rahasia-super-aman';
```

## API Endpoints

Base URL: http://localhost:5000

- POST /api/auth/register
	- Deskripsi: Registrasi pengguna baru
	- Body (JSON): { "name": "Nama", "email": "email@contoh.com", "password": "rahasia" }
	- Response: { message: 'Registrasi berhasil' }

- POST /api/auth/login
	- Deskripsi: Login, mengembalikan token JWT
	- Body (JSON): { "email": "email@contoh.com", "password": "rahasia" }
	- Response: { token: "<JWT>" }

Header Authorization untuk route yang dilindungi: `Authorization: Bearer <token>`

- GET /api/items
	- Deskripsi: Ambil daftar items (dilindungi)
	- Response: Array of items

- POST /api/items
	- Deskripsi: Tambah item baru (dilindungi)
	- Body (JSON): { "title": "Judul", "description": "Deskripsi" }
	- Response: { message: 'Item ditambahkan', item: { id, title, description } }

- PUT /api/items/:id
	- Deskripsi: Perbarui item berdasarkan id (dilindungi)
	- Body (JSON): { "title": "Judul baru", "description": "Deskripsi baru" }
	- Response: { message: 'Item diperbarui' }

- DELETE /api/items/:id
	- Deskripsi: Hapus item berdasarkan id (dilindungi)
	- Response: { message: 'Item dihapus' }

## Contoh penggunaan (curl)

1) Registrasi:

```powershell
curl -X POST http://localhost:5000/api/auth/register -H "Content-Type: application/json" -d '{"name":"Budi","email":"budi@example.com","password":"rahasia"}'
```

2) Login (ambil token):

```powershell
curl -X POST http://localhost:5000/api/auth/login -H "Content-Type: application/json" -d '{"email":"budi@example.com","password":"rahasia"}'
```

Response akan berisi `{ "token": "..." }`. Gunakan token ini untuk request selanjutnya.

3) Menambah item (menggunakan token):

```powershell
curl -X POST http://localhost:5000/api/items -H "Content-Type: application/json" -H "Authorization: Bearer <TOKEN>" -d '{"title":"Contoh","description":"Deskripsi"}'
```

## Bentuk data

- User (in-memory): { id, name, email, password(hashed) }
- Item: { id, title, description }

## Struktur folder (singkat)

- `server.js` - file utama Express
- `package.json` - daftar dependency
- `dokumentasi/postman` - koleksi Postman (jika ada)

## Keamanan & Pengembangan

- Jangan simpan `SECRET_KEY` secara hard-coded untuk produksi. Gunakan environment variable.
- Data saat ini hanya tersimpan di memori; untuk persistensi gunakan database.

## License

Lisensi: ISC (sesuai `package.json`). Sesuaikan jika perlu.



