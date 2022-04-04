## Installation steps

1. Ensure you have python3 installed

2. Clone the repository
3. create a virtual environment using `virtualenv venv`
4. Activate the virtual environment by running `source venv/bin/activate`

- On Windows use `.\venv\Scripts\activate`

5. Install the dependencies using `pip install -r requirements.txt`

6. Setup MySQL database using configuration in settings.py
7. Run the `python manage.py makemigrations`
8. Migrate existing db tables by running `python manage.py migrate`

9. Run the django development server using `python manage.py runserver`
10. First upload the 2D molecule images to the system (Sample images in src/images folder)
11. Then check the image similarity.
