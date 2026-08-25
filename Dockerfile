# D8 Handover Package — containerized reproduction environment
# Build:  docker build -t roed-repro .
# Run:    docker run --rm -v $(pwd)/out:/app/results roed-repro

FROM python:3.11-slim

WORKDIR /app

COPY scripts/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY scripts/ ./scripts/

RUN mkdir -p /app/data /app/results

# Full pipeline, in order. SEED=42 is fixed inside the scripts themselves.
CMD python scripts/roed_synthetic_generator.py --output ./data --n_normal 35000 --n_attack 4200 && \
    python scripts/roed_s1_evaluate.py --input ./data/roed_combined_dataset.csv --output ./results && \
    python scripts/roed_s2_evaluate.py --input ./data/roed_combined_dataset.csv --output ./results && \
    python scripts/roed_cvss_calculator.py --all --output ./results/cvss_results.json && \
    echo "Pipeline complete. Compare ./results to the results/ folder in this package."
