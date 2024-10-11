from django.urls import path
from . import views
urlpatterns = [
    path('', views.index, name='records'),
    path('add-program', views.add_program, name='add-program'),
]
