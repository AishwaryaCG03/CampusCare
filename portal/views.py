from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.mail import send_mail
from django.conf import settings
from .forms import SignUpForm, ComplaintForm, RatingForm
from .models import Complaint, Category, Profile
from django.utils import timezone
from django.db.models import Count, Avg
from datetime import timedelta
from textblob import TextBlob  # Import TextBlob for sentiment analysis
import random
from django.contrib.auth.models import User

from django.utils import timezone




def send_resolution_email(complaint):
    subject = 'Your Complaint has been Resolved'
    message = f'Your complaint (ID: {complaint.id}) has been resolved. Thank you for your patience!'
    recipient_list = [complaint.user.email] if complaint.user else []
    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, recipient_list)



@login_required
def dashboard(request):
    profile = Profile.objects.get(user=request.user)
    role = profile.role

    if role in ['student', 'faculty', 'non_teaching', 'worker']:
        complaints = Complaint.objects.filter(user=request.user).order_by('-created_at')
    elif role in ['class_teacher', 'hod', 'principal']:
        complaints = Complaint.objects.filter(assigned_to=request.user).order_by('-created_at')
    else:
        complaints = Complaint.objects.all().order_by('-created_at')

    # Prepare data for charts and stats
    categories = Category.objects.all()
    category_labels = [cat.name for cat in categories]
    category_counts = [complaints.filter(category=cat).count() for cat in categories]

    status_choices = ['Pending', 'Escalated', 'Resolved']
    status_counts = [complaints.filter(status=status).count() for status in status_choices]

    total_complaints = complaints.count()
    resolved_count = complaints.filter(status='Resolved').count()
    resolved_rate = (resolved_count / total_complaints * 100) if total_complaints else 0
    avg_rating = complaints.aggregate(avg=Avg('rating'))['avg'] or 0

    # Urgent complaints with negative sentiment (<-0.3)
    urgent_complaints = complaints.filter(sentiment__lt=-0.3).order_by('sentiment')

    escalation_count = Complaint.objects.filter(status='Escalated').count() if role == 'admin' else 0
    overdue_count = 0
    if role == 'admin':
        overdue_count = Complaint.objects.filter(
            status__in=['Pending', 'Escalated'],
            created_at__lte=timezone.now() - timedelta(days=14)
        ).count()

    context = {
        'complaints': complaints,
        'urgent_complaints': urgent_complaints,
        'role': role,
        'category_labels': category_labels,
        'category_counts': category_counts,
        'status_labels': status_choices,
        'status_counts': status_counts,
        'total_complaints': total_complaints,
        'resolved_count': resolved_count,
        'resolved_rate': round(resolved_rate, 2),
        'avg_rating': round(avg_rating, 2),
        'escalation_count': escalation_count,
        'overdue_count': overdue_count,
    }
    return render(request, 'portal/dashboard.html', context)

@login_required
def create_complaint(request):
    if request.method == 'POST':
        form = ComplaintForm(request.POST, request.FILES)
        if form.is_valid():
            complaint = form.save(commit=False)
            analysis = TextBlob(complaint.description)
            complaint.sentiment = analysis.sentiment.polarity
            anonymous = form.cleaned_data.get('anonymous')
            if anonymous:
                complaint.anonymous = True
                complaint.user = None
            else:
                complaint.user = request.user
                complaint.anonymous = False
            complaint.save()
            messages.success(request, 'Complaint submitted successfully')
            return redirect('dashboard')
    else:
        form = ComplaintForm()
    return render(request, 'portal/complaint_create.html', {'form': form})

@login_required
def complaint_detail(request, pk):
    complaint = get_object_or_404(Complaint, pk=pk)
    rating_given = complaint.rating is not None

    if request.method == 'POST':
        if 'resolve' in request.POST:
            complaint.status = 'Resolved'
            complaint.resolved_at = timezone.now()
            if not complaint.email_sent:
                send_resolution_email(complaint)
                complaint.email_sent = True
            complaint.save()
            messages.success(request, 'Complaint marked as resolved.')
            return redirect('complaint_detail', pk=pk)
        else:
            form = RatingForm(request.POST)
            if form.is_valid():
                complaint.rating = form.cleaned_data['rating']
                complaint.save()
                messages.success(request, 'Thank you for your rating!')
                return redirect('complaint_detail', pk=pk)
    else:
        form = RatingForm()

    return render(request, 'portal/complaint_detail.html', {
        'complaint': complaint,
        'form': form,
        'rating_given': rating_given,
    })

@login_required
def profile(request):
    return render(request, 'portal/profile.html')
