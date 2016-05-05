from django.conf.urls import patterns, include, url


# Uncomment the next two lines to enable the admin:
# from django.contrib import admin
# admin.autodiscover()

urlpatterns = patterns('',
    # Examples:
    # url(r'^$', 'gui.views.home', name='home'),
    # url(r'^gui/', include('gui.foo.urls')),

    # Uncomment the admin/doc line below to enable admin documentation:
    # url(r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    # url(r'^admin/', include(admin.site.urls)),
	
	#url(r'^$', 'fetch.views.index', name='index'),
	url(r'^$', 'fetch.views.main', name='main'),
	url(r'^index', 'fetch.views.index', name='index'),
	url(r'^execute1', 'fetch.views.execute1', name='execute1'),
	url(r'^upload', 'fetch.views.upload', name='upload'),
	url(r'^craft','fetch.views.craft',name='craft'),
	url(r'^result','fetch.views.result',name='result'),
	url(r'^execute2', 'fetch.views.execute2', name='execute2'),
)
