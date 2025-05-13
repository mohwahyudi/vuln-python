# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container
COPY . /app/

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir flask defusedxml

# Make port 5000 available to the world outside this container
EXPOSE 5000

# Define environment variable to indicate production mode
ENV PRODUCTION=true

# Set a secure random secret key (this is just for demonstration)
# In real production, you would inject this as a build arg or at runtime
ENV SECRET_KEY=this_would_be_a_secure_random_key_in_production

# Set admin password (again, for demonstration only)
ENV ADMIN_PASSWORD=SecureAdminPassword123!

# Run the application when the container launches
# For a real production app, you would use a proper WSGI server like gunicorn
CMD ["python", "secure_app.py"]

# Security note: For a real production application, you would:
# 1. Use a non-root user
# 2. Use a proper WSGI server like gunicorn
# 3. Set up proper logging
# 4. Use Docker secrets or a vault service for sensitive information
# 5. Consider a multi-stage build to minimize the final image size