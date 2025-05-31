from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .models import Complaint

class SignUpForm(UserCreationForm):
    ROLE_CHOICES = (
        ('student', 'Student'),
        ('faculty', 'Faculty'),
        ('non_teaching', 'Non Teaching Faculty'),
        ('worker', 'Worker'),
    )
    role = forms.ChoiceField(choices=ROLE_CHOICES, required=True)

    class Meta:
        model = User
        fields = ('username', 'email', 'password1', 'password2', 'role')

class ComplaintForm(forms.ModelForm):
    anonymous = forms.BooleanField(required=False, initial=False, label="Post Anonymously")
    class Meta:
        model = Complaint
        fields = ['category', 'description', 'evidence', 'anonymous']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 4}),
        }

class RatingForm(forms.Form):
    rating = forms.IntegerField(min_value=1, max_value=5, widget=forms.NumberInput(attrs={'type':'range','min':'1','max':'5'}))

