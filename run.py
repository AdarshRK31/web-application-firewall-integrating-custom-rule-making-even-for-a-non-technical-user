# run.py
from app import create_app
from app.detector import seed_attack_patterns, init_detector
import logging

# ---------------------------------------------------
# ✅ Create Flask App
# ---------------------------------------------------
app = create_app()

# ---------------------------------------------------
#  Seed and Initialize within Context
# ---------------------------------------------------
if __name__ == "__main__":
    with app.app_context():
        try:
            # 1️⃣ Seed attack patterns
            seeded = seed_attack_patterns(app)
            if seeded:
                print(f"[INIT] Seeded {seeded} attack patterns into DB.")

            # 2️⃣ Initialize detector safely
            init_detector(app)
            print("[INIT] WAF Detector initialized successfully.")
        except Exception as e:
            print(f"[WARN] Initialization failed: {e}")

    # ---------------------------------------------------
    # ⚙️ Logging Setup
# ---------------------------------------------------
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler()]
    )

    # ---------------------------------------------------
    # 🚀 Run Flask App
    # ---------------------------------------------------
    app.run(host="0.0.0.0", port=5000, debug=True)

