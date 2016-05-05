
from django.conf.urls import patterns, url

from fetch import views

urlpatterns = patterns('',
	url(r'^$', views.index, name='index')
	url(r'^execute1$', views.execute1, name='execute1'),
)
