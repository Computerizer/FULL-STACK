import {PostSubs}  from './handleSubs.js'

/* Global Variables */
const absURL = 'https://computerizr.com' // website domain URL 
const baseURL = '/blog/post/'
const postsURL = '/blog/recent-posts/'
const postURL = document.title

const postText = document.querySelector(".post__text")
const postTitle = document.querySelector(".post__title")
const author = document.querySelector(".author")
const dateSpan = document.querySelector(".date")
const heroImage = document.querySelector(".hero")
const recentsNav = document.querySelector(".recents__nav")
const subsBtn = document.querySelector(".subs-submit")
const subsDiv = document.querySelector(".subscribe_form")
const fName = document.getElementById('f-name')
const lName = document.getElementById('l-name')
const eMail = document.getElementById('e-mail')
const errorP = document.getElementById('error')

// Main functions
function main() {

    getPost()
    .then((post) => {
        renderPost(post)
    })

    getPosts()
    .then((posts) => {
        renderPosts(posts)
    })

    subsBtn.addEventListener('click', subscribe)
}

/*
*
* Script Functions
* 
*/

// Fetching post information from databas function
const getPost = async () => {
    const response = await fetch(absURL + baseURL + postURL)
    try {
        const post = response.json()
        return post
    } catch (error) {
        console.error('Failing to fetch posts from database!')
    }
}

// Fetching posts from databas function
const getPosts = async () => {
    const response = await fetch(absURL + postsURL + "6/1")
    try {
        const posts = response.json()
        return posts
    } catch (error) {
        console.error('Failing to fetch posts from database!')
    }
}

// Rendering post
function renderPost(post) {
    let dateHolder = post.publish_date.slice(0, 10)
    let date = "";

    date = dateHolder.slice(8, 10) + "/" + dateHolder.slice(5, 7) + "/" + dateHolder.slice(0, 4) 

    postTitle.innerText = post.title
    author.innerText = post.author
    dateSpan.innerText = date
    postText.innerHTML = post.body
    heroImage.src = post.image
}

// Rendering more posts section
function renderPosts(posts) {
    let fragmentDiv = document.createDocumentFragment()
    posts.forEach(post => {
        let cardDiv = document.createElement("div")
        cardDiv.classList.add("post-card")
        cardDiv.dataset.url = post.post_url
        cardDiv.innerHTML = `
            <img src="${post.image}" alt="post image" class="card__img">
            <div class="card__text">
                <h3 class="post-card__title">
                    ${post.title}
                </h3>
            </div>
        `

    fragmentDiv.appendChild(cardDiv)
    });
    fragmentDiv.childNodes.forEach(post => {
        post.addEventListener('click', redirectUrl)
    })
    recentsNav.appendChild(fragmentDiv)
}

// Routing function
function redirectUrl(e) {
    e.preventDefault()
    window.location.href = window.location.href.slice(-8, 0) + `/${e.currentTarget.dataset.url}`
}

// Thanks message for subscribed user
function renderThanks() {
    subsDiv.innerHTML = ''
    document.querySelector('.subs__title').innerText = "Thanks for subscribing\n Stay computerized!"
}

// post subs fetch
function subscribe(e) {
    e.preventDefault()
    errorP.innerText = ""


    fName.classList.remove("errorField")
    fName.previousElementSibling.firstElementChild.innerText = ''
    lName.classList.remove("errorField")
    lName.previousElementSibling.firstElementChild.innerText = ''
    eMail.classList.remove("errorField")
    eMail.previousElementSibling.firstElementChild.innerText = ''

    const backData = {
        'firstName': fName.value,
        'lastName': lName.value,
        'email': eMail.value
    }

    for (const key in backData) {
        if (backData[key] === '') {
            if (key === 'firstName') {
                fName.classList.add("errorField")
                fName.previousElementSibling.firstElementChild.innerText = "This field can't be empty!"
                return
            } else if (key === 'lastName') {
                lName.classList.add("errorField")
                lName.previousElementSibling.firstElementChild.innerText = "This field can't be empty!"
                return
            } else if (key === 'email') {
                eMail.classList.add("errorField")
                eMail.previousElementSibling.firstElementChild.innerText = "This field can't be empty!"
                return
            }
        }
    }

    PostSubs(backData)
    .then(res => {
        handleErrors(res)
    })
}

// handle Subscribe Errors
function handleErrors(res) {

    fName.classList.remove("errorField")
    lName.classList.remove("errorField")
    eMail.classList.remove("errorField")

    if (res === 'success') {
        renderThanks()
    } else {
        let msg = JSON.parse(res)
        if (msg.title === "Member Exists") {
            eMail.classList.add("errorField")
            eMail.previousElementSibling.firstElementChild.innerText = "This email already exists!"
        } else {
            eMail.classList.add("errorField")
            eMail.previousElementSibling.firstElementChild.innerText = msg.detail
        }
    }
}

main()