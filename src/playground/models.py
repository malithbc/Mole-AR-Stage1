from django.db import models

import uuid
import os


class Image(models.Model):

    def get_file_path(instance, filename):
        ext = filename.split('.')[-1]
        filename = "%s.%s" % (uuid.uuid4(), ext)
        return os.path.join('Object3D/', filename)
    
    image_id = models.CharField(max_length=100)
    image = models.ImageField(upload_to='images/')
    user_id = models.CharField(max_length=100)
    object_3D = models.FileField(upload_to='Object3D/')
    mtl = models.FileField(upload_to='Object3D/')

    def get_image(self):
        return self.image

# class ExtractFeature(models.Model):
#     image_id = models.CharField(max_length=50)
#     descriptor = models.TextField()

#     def get_vector(self):
#         return self.descriptor

class TemporaryImage(models.Model):
    image_id = models.CharField(max_length=100)
    image = models.ImageField(upload_to='temporary_images/')

    def get_image(self):
        return self.image
