from django.contrib.auth import get_user_model
from rest_framework import serializers

User = get_user_model()


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(style={'input_type': 'password'}, write_only=True,required=False)
    class Meta:
        model = User
        fields = ['last_name','first_name','phone_number','email','password']
        extra_kwargs = {
            'last_name': {'required': False},
            'first_name': {'required': False},
            'phone_number': {'required': False},
            'email': {'required': False},
        }

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        user = User(**validated_data)
        if password:
            user.set_password(password)
        user.save()
        return user

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        if password:
            instance.set_password(password)
        instance.save()
        return instance


class UserUpdateSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ['first_name','last_name','phone_number','email','address','image','created_at','updated_at']

    def update(self, instance, validated_data):
        for attr, value in validated_data.items():
            if value:
                setattr(instance, attr, value)

        if 'image' in validated_data and instance.image:
            instance.image.delete(save=False)

        instance.save()
        return instance
