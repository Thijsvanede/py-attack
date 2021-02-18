from django.shortcuts import render
from py_attack.attack import ATTACK

def index(request):
    # Set empty context
    context = dict()

    # Return webpage
    return render(request, "attack/index.html", context)
