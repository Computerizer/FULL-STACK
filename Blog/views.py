from sqlite3 import IntegrityError
from django.shortcuts import render
from rest_framework.response import Response
from Oauth.models import CustomUser
from .models import Author, Post, Post_Image, Comment, LikeComment, LikePost, Sale, Category
from .serializer import AuthorSerializer, ImagePostSerializer, PostSerializer, LikePostSerializer, RecentPostSerializer, CommentSerializer, LikeCommentSerializer, SaleSerializer, CategorySerializer
from django.core.files.storage import default_storage
from rest_framework.permissions import IsAuthenticated,IsAdminUser,IsAuthenticatedOrReadOnly,AllowAny
from rest_framework.authentication import TokenAuthentication
from rest_framework.decorators import api_view,permission_classes,authentication_classes
from rest_framework.views import APIView
from django.db.models import Q
from django.core.paginator import Paginator



# Create your views here.
@api_view(['GET'])
def getSales(request, num_of_sales):
    sales = Sale.objects.all()
    serializer = SaleSerializer(sales, many = True)
    return Response(serializer.data[0:num_of_sales])


@api_view(['GET'])
def getCategories(request):
    categories = Category.objects.all()
    serializer = CategorySerializer(categories, many = True)

    posts = []
    for category in serializer.data:
        for postId in category["posts"]:
            post = Post.objects.get(id = postId)
            posts += [post.title]
        category['posts'] = posts
        posts = []      
        
    return Response(serializer.data)

@api_view(["GET"])
def getRecentPosts(request, num_of_posts, page_num):
    posts = Post.objects.filter(status = 'Published').order_by('publish_date')
    objects = Paginator(posts, num_of_posts)
    if page_num <= len(objects.page_range):
        serializer = RecentPostSerializer(objects.page(page_num), many=True)
        
        for post in serializer.data:
            cureent_post = Post.objects.get(id = post["id"])
            post['post_url'] = cureent_post.get_absolute_url()

        return Response(serializer.data)
    else:
        return Response('Out of range')        

@api_view(["GET"])
def getPostsOrdered(request, order, num_of_posts):
    posts = Post.objects.filter(status = 'Published').order_by(order).reverse()    
    serializer = RecentPostSerializer(posts, many=True)
    return Response(serializer.data[0:num_of_posts])   

@api_view(["GET"])
def getPost(request, title):
    post = Post.objects.get(title = title)
    images = Post_Image.objects.filter(post = post)
    image_serializer = ImagePostSerializer(images, many = True)

    serializer = PostSerializer(post)
    f = default_storage.open(str(post.body))
    body = f.read().decode("utf-8")

    # replacing image title in html to image link
    for image in image_serializer.data:
        # [] inside f'' not working
        photo = image['title']
        index = body.find(f'src="{photo}"')
        
        # checking if image src in the file( index = -1 means not found)
        if index != -1:
            image = image['image']
            body = body.replace(body[index : index + len(f"src='{photo}'")] , f'src="{image}"')
        else:
            # checking if there src = '' instead of src = ""
            index = body.find(f"src='{photo}'") 
            if index != -1:
                image = image['image']
                body = body.replace(body[index : index + len(f"src='{photo}'")] , f"src='{image}'") 
            

    data = {
            'title': post.title,
            'author' : post.author.name,
            'body' : body,
            'description' : post.description,
            'image': serializer.data['image'],
            'publish_date': post.publish_date,
            'likes' : post.likes,
            'dislikes' : post.dislikes,
            'views' : post.views
        }
    return Response(data, status=200)



@api_view(["POST"])
def viewPost(request):
    post = Post.objects.get(title = request.data['post'])

    post.views += 1
    post.save()
    return Response("Post Viewed")
    
@api_view(['GET'])
def getComments(request, post_title):
    post = Post.objects.get(title = post_title)
    comments = Comment.objects.filter(post = post)
    serializer = CommentSerializer(comments, many = True)
    for i in serializer.data:
        user = CustomUser.objects.get(id = i['user'])
        i['user'] = user.username
        i['post'] = post.title
    return Response(serializer.data)


class CreateComment(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def post(self ,request):
        post = Post.objects.get(title = request.data['post'])
        user = CustomUser.objects.get(username= request.data['user'])
        if user == request.user:
            data = {
                'body' : request.data['body'],
                'user' : user.id,
                'post' : post.id
            }
            serializer = CommentSerializer(data= data)
            if serializer.is_valid():
                serializer.save()
            return Response(serializer.data)  
        else:
            return Response("You don't have permission to do this")


class LikePostView(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        post = Post.objects.get(title = request.data['post'])
        user = CustomUser.objects.get(username = request.data['user'])
        like_state = 'liked'
        if user == request.user:
            #check if already diliked or liked by user 
            try:
                like_post = LikePost.objects.get(post = post, user = user)
                if like_post.like_state == like_state:
                    return Response('post already liked by user')
                else:    
                    post.likes += 1
                    post.dislikes -= 1
                    post.save()
                        
                    like_post.like_state = like_state
                    like_post.save()
                    
            except:    
                like_post = LikePost( post = post, user = user, like_state = like_state)
                like_post.save()

                post.likes += 1
                post.save()

            return Response('post liked')
        else:
            return Response("You don't have permission to edit this")    


class DislikePost(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        post = Post.objects.get(title = request.data['post'])
        user = CustomUser.objects.get(username = request.data['user'])

        if request.user == user:
            like_state = 'disliked'
            #check if already disliked or liked by user 
            try:
                dislike_post = LikePost.objects.get(post = post, user = user)
                if dislike_post.like_state == 'disliked':
                    return Response('post already disliked by user')
                else:    
                    dislike_post.like_state = like_state
                    dislike_post.save()

                    post.likes -= 1
                    post.dislikes += 1
                    post.save()
            except:    
                dislike_post = LikePost( post = post, user = user, like_state = like_state)
                dislike_post.save()

                post.dislikes += 1
                post.save()

            return Response('post disliked')
        else:
            return Response("You don't have permission to edit this")    


@api_view(['GET'])
def getPostLikes(request, title):
    post = Post.objects.get(title = title)
    likes = LikePost.objects.filter(post= post, like_state = 'liked')
    serializer = LikePostSerializer(likes, many = True)

    #using username and title insted of id number
    for i in serializer.data:
        user = CustomUser.objects.get(id = i['user'])
        i['user'] = user.username
        i['post'] = post.title
        

    return Response(serializer.data)


@api_view(['GET'])
def getPostDislikes(request, title):
    post = Post.objects.get(title = title)
    dislikes = LikePost.objects.filter(post= post, like_state = 'disliked')
    serializer = LikePostSerializer(dislikes, many = True)

    #using username and title insted of id number
    for i in serializer.data:
        user = CustomUser.objects.get(id = i['user'])
        i['user'] = user.username
        i['post'] = post.title
        

    return Response(serializer.data)




class UnlikePost(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)


    def post(self, request):
        post = Post.objects.get(title = request.data['post'])
        user = CustomUser.objects.get(username = request.data['user'])
        if user == request.user:
            try:
                liked_post = LikePost.objects.get(post = post, user = user, like_state = 'liked')
                liked_post.delete()

                if post.likes != 0:
                    post.likes -= 1
                post.save()
            except:
                return Response("post isn't liked")    

            return Response('post unliked')    
        else:
            return Response("You don't have permission to do this")


class UndislikePost(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        post = Post.objects.get(title = request.data['post'])
        user = CustomUser.objects.get(username = request.data['user'])
        if user == request.user:
            try:
                liked_post = LikePost.objects.get(post = post, user = user, like_state = 'disliked') 
                liked_post.delete()

                if post.dislikes != 0:
                    post.dislikes -= 1
                post.save()
            except:
                return Response("post isn't disliked")     

            return Response('post undisliked')    
        else:
            return Response("You don't have permission to do this")    


class LikeCommentView(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)
    def post(self, request):
        comment_user = CustomUser.objects.get(username = request.data['comment_user'])
        post = Post.objects.get(title = request.data['post'])

        comment = Comment.objects.get(body = request.data['body'], user = comment_user, post = post)
        user = CustomUser.objects.get(username = request.data['user'])
        if user == request.user:
            try:
                like_comment = LikeComment.objects.get(user = user, comment = comment)
                return Response('comment already liked by this user')
            except:
                like_comment = LikeComment(comment = comment, user = user)
                like_comment.save()

                comment.likes += 1
                comment.save()    

            return Response('comment liked')
        else:
            return Response("You don't have permission to do this")    


class UnlikeComment(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        comment_user = CustomUser.objects.get(username = request.data['comment_user'])
        post = Post.objects.get(title = request.data['post'])

        comment = Comment.objects.get(body = request.data['body'], user = comment_user, post = post)
        user = CustomUser.objects.get(username = request.data['user'])
        if user == request.user:
            try:
                like_comment = LikeComment.objects.get(comment = comment , user = user)
                like_comment.delete()

                if comment.likes != 0:
                    comment.likes -= 1
                comment.save()
            except:
                return Response("This comment isn't liked by this user")    

            return Response('comment unliked')       
        else:
            return Response("You don't have permission to do this")    



@api_view(['GET'])
def getCommentLikes(request, id):
    comment = Comment.objects.get(id = id)
    comment_likes = LikeComment.objects.filter(comment = comment)
    serializer = LikeCommentSerializer(comment_likes, many = True)
    for i in serializer.data:
        i['comment'] = comment.body
        i['user'] = comment.user.username

    return Response(serializer.data)

@api_view(["GET"])
def searchBlog(request, query):
    posts = Post.objects.filter(Q(title__icontains = query) | Q(description__icontains = query))
    categories = Category.objects.filter(Q(title__icontains = query))

    serializer = RecentPostSerializer(posts, many = True)
    categoriesSerializer = CategorySerializer(categories, many = True)
    
    data = {}
    data['posts'] = serializer.data
    data['categories'] = categoriesSerializer.data
    
    return Response(data)