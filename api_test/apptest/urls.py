from django.urls import path
from . import views

urlpatterns = [
    path('user_profile/', views.UserProfile.as_view(), name='user_profile'),
    path('create_user/', views.CreateUser.as_view(), name='create_user'),
    path('view_user/<int:pk>/', views.ViewUser.as_view(), name='view_user'),
    path('list_user/', views.ListUser.as_view(), name='list_user'),
    path('update_user/<int:pk>/', views.UpdateUser.as_view(), name='update_user'),
    path('delete_user/<int:pk>/', views.DeleteUser.as_view(), name='delete_user'),
    path('login/', views.Login.as_view(), name='login'),
    path('logout/', views.Logout.as_view(), name='logout'),
]
