from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.core.validators import MinValueValidator, MaxValueValidator
from django.db.models.signals import post_save
from django.dispatch import receiver

class Profile(models.Model):
    USER_ROLES = (
        ('student', 'Student'),
        ('faculty', 'Faculty'),
        ('non_teaching', 'Non Teaching Faculty'),
        ('worker', 'Worker'),
        ('guest', 'Guest'),
    )
    user = models.OneToOneField(User, on_delete=models.CASCADE, null=True, blank=True)
    role = models.CharField(max_length=20, choices=USER_ROLES, default='student')
    # extra fields if needed

    def __str__(self):
        if self.user:
            return f"{self.user.username} - {self.role}"
        return f"Guest - {self.role}"

class Category(models.Model):
    name = models.CharField(max_length=100)

    def __str__(self):
        return self.name

class Complaint(models.Model):
    
    user = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)
    anonymous = models.BooleanField(default=False)
    category = models.ForeignKey(Category, on_delete=models.SET_NULL, null=True)
    description = models.TextField()
    evidence = models.FileField(upload_to='evidence/', null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=(
    ('Pending', 'Pending'),
    ('Escalated', 'Escalated'),
    ('Resolved', 'Resolved'),
    ), default='Pending')
    rating = models.PositiveIntegerField(null=True, blank=True, validators=[MinValueValidator(1), MaxValueValidator(5)])
    escalation_level = models.PositiveIntegerField(default=0)  # 0: initial, 1: class teacher, 2: HOD, 3: Principal
    email_sent = models.BooleanField(default=False) 
    sentiment = models.FloatField(null=True, blank=True)
    
    
    
    assigned_to = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='assigned_complaints')

    
    
     # New field to track email notification
    def is_overdue(self):
        if self.status != 'Resolved' and (timezone.now() - self.created_at).days > 14:
            return True
        return False

    def escalate(self):
        if self.escalation_level < 3:
            self.escalation_level += 1
            self.status = 'Escalated'
            self.save()

    def __str__(self):
        return f"Complaint {self.id} - {self.category.name} - {self.status}"
@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.profile.save()

