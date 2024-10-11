from django.shortcuts import render

# Create your views here.

def index(request):
    return render(request,'records/index.html')


def add_program(request):
    return render(request,'records/add_program.html')