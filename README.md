# Hybrid IDS Todo Demo

This project gives you:

- a Todo website that acts as the victim system
- a live IDS dashboard beside it
- dedicated `Home`, `Todo Site`, `Live Monitor`, `Reports`, and `Split Lab` pages
- hybrid detection for brute-force and DDoS traffic
- automatic mitigation with rate limiting and IP blocking
- Supabase-backed persistence for users, todos, alerts, and telemetry
- a CSV training dataset used by the ML classifier

If Supabase is not configured yet, the app falls back to `data/local_store.json` so the demo still runs.

## Quick Start

1. Install dependencies:

```powershell
pip install -r requirements.txt
```

2. Optional but recommended: copy `.env.example` to `.env` and fill in your Supabase values.
3. If using Supabase, run the SQL in `supabase_schema.sql` inside the Supabase SQL editor.
4. Start the app:

```powershell
python app.py
```

5. Open `http://127.0.0.1:5000`

## Main Routes

- `/` home and navigation
- `/todo` working Todo website with normal HTML login/register/task forms
- `/monitor` live IDS page
- `/reports` analysis report page
- `/lab` split-screen combined view

## Demo Login

- Username: `analyst`
- Password: `Defend123!`

## Attack Demo

Use the dashboard buttons or run the attacker script from another terminal:

```powershell
python attacker.py --mode both --base-url http://127.0.0.1:5000 --ip 185.234.219.12
```

## Dataset

The detector reads `data/ids_training_dataset.csv` and uses it to train the ML portion of the hybrid IDS model.
