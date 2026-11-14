# Wude Mart Backend

Fresh backend project for the Wude Mart Android customer app and separate admin website.

## Included in this first backend foundation

- FastAPI server and interactive API docs
- Customer registration and login
- Admin account created from environment variables
- Role-based admin protection
- Product listing and admin product management
- Customer order creation and order history
- Payment-proof image upload
- Manual admin payment review (uploading proof never auto-approves payment)
- Admin order and payment views

## Run locally

1. Install Python 3.10+.
2. Open a terminal in this folder.
3. Create and activate a virtual environment.
4. Run:

   ```bash
   pip install -r requirements.txt
   ```

5. Set `WUDE_SECRET_KEY`, `WUDE_ADMIN_EMAIL`, and `WUDE_ADMIN_PASSWORD`.
6. Start the API:

   ```bash
   uvicorn main:app --reload
   ```

7. Open `http://127.0.0.1:8000/docs`.

## Important before public deployment

This is a development foundation, not a production deployment yet. It uses a local SQLite database and local image storage. A deployed server needs persistent storage or managed PostgreSQL/object storage, HTTPS, a real trusted CORS origin, backups, rate limiting, and a private way to serve payment proof images to authorized admins. Do not commit `.env` files, real passwords, API keys, or customer payment screenshots to GitHub.

Payment instructions/methods have intentionally not been hard-coded because Wude Mart's accepted payment methods have not been specified yet.
