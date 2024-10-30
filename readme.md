Download Popper and create path in global environment for it
Download Tesseract OCR and same make path

now first command in project

 python -m venv my_venv
 pip install -r requirements.txt    
 python.exe -m pip install --upgrade pip    
 my_venv\Scripts\activate
 cd ccswebsite

First make sure postgresql have na db thesisDB and backup then do this

 python manage.py makemigrations

 python manage.py migrate 

 python manage.py runserver