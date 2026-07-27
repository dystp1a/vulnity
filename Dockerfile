# Dockerfile
FROM python:3.11-slim

# Install Docker CLI and Git (Git is needed if you use it in subprocesses)
RUN apt-get update && \
    apt-get install -y docker.io git && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Create a requirements file or install directly
# RUN pip install requests streamlit
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy all your Python scripts into the container
COPY . .

# Expose Streamlit's default port
EXPOSE 8501

# Start the Streamlit GUI
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]