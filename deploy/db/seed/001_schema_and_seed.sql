-- Fake, regulated-shaped data for the gateway demo.
-- Theme: a small clinic. PHI/PII columns (SSN, DOB, email, phone, diagnosis,
-- insurance + card data) are what the gateway's argument redaction and
-- "denied destructive SQL" beats are about.
--
-- NOTHING HERE IS REAL. SSNs use the 900-999 area range, which the SSA has
-- never issued, so the data is unmistakably synthetic.

CREATE TABLE patients (
    id            serial PRIMARY KEY,
    mrn           text        NOT NULL UNIQUE,   -- medical record number
    first_name    text        NOT NULL,
    last_name     text        NOT NULL,
    ssn           text        NOT NULL,          -- PHI/PII
    dob           date        NOT NULL,          -- PHI
    email         text        NOT NULL,          -- PII
    phone         text        NOT NULL,          -- PII
    diagnosis     text        NOT NULL,          -- PHI
    insurance_id  text        NOT NULL
);

CREATE TABLE visits (
    id          serial PRIMARY KEY,
    patient_id  integer NOT NULL REFERENCES patients(id),
    visit_date  date    NOT NULL,
    provider    text    NOT NULL,
    notes       text    NOT NULL                 -- PHI (free-text clinical notes)
);

CREATE TABLE billing (
    id           serial PRIMARY KEY,
    patient_id   integer NOT NULL REFERENCES patients(id),
    card_last4   text    NOT NULL,               -- PCI-shaped
    amount_cents integer NOT NULL,
    paid         boolean NOT NULL DEFAULT false
);

-- 40 synthetic patients, deterministic so the demo is reproducible.
INSERT INTO patients (mrn, first_name, last_name, ssn, dob, email, phone, diagnosis, insurance_id)
SELECT
    'MRN' || lpad(g::text, 6, '0'),
    (ARRAY['James','Mary','Robert','Patricia','John','Jennifer','Michael','Linda','David','Maria'])[1 + (g % 10)],
    (ARRAY['Smith','Johnson','Williams','Brown','Jones','Garcia','Miller','Davis','Rodriguez','Martinez'])[1 + (g % 10)],
    '9' || lpad((10 + g % 89)::text, 2, '0') || '-' || lpad((g % 99)::text, 2, '0') || '-' || lpad((1000 + g)::text, 4, '0'),
    DATE '1950-01-01' + ((g * 137) % 20000),
    'patient' || g || '@example.test',
    '(555) ' || lpad((100 + g)::text, 3, '0') || '-' || lpad((2000 + g * 7)::text, 4, '0'),
    (ARRAY['Type 2 Diabetes','Hypertension','Asthma','Major Depressive Disorder','Hyperlipidemia',
           'Atrial Fibrillation','Hypothyroidism','GERD','Osteoarthritis','Migraine'])[1 + (g % 10)],
    'INS-' || lpad((500000 + g * 13)::text, 7, '0')
FROM generate_series(1, 40) AS g;

INSERT INTO visits (patient_id, visit_date, provider, notes)
SELECT
    1 + (g % 40),
    DATE '2025-01-01' + ((g * 9) % 360),
    (ARRAY['Dr. Patel','Dr. Nguyen','Dr. Okafor','Dr. Schmidt'])[1 + (g % 4)],
    'Routine follow-up; medication reconciled; vitals within normal limits.'
FROM generate_series(1, 80) AS g;

INSERT INTO billing (patient_id, card_last4, amount_cents, paid)
SELECT
    1 + (g % 40),
    lpad((g * 211 % 10000)::text, 4, '0'),
    1500 + (g * 317) % 48500,
    (g % 3 = 0)
FROM generate_series(1, 60) AS g;
