const postText = document.querySelector(".post__text")
const postTitle = document.querySelector(".post__title")
const author = document.querySelector(".author")
const dateSpan = document.querySelector(".date")
const heroImage = document.querySelector(".hero")
const recentsNav = document.querySelector(".recents__nav")
const statisDiv = document.querySelector(".statis")
let posts = ""
<<<<<<< HEAD
=======

>>>>>>> New-Frontend
let post;


const div = async () => {
<<<<<<< HEAD
    let response = await fetch('http://computerizr/blog/post/' + document.title)
=======
    let response = await fetch('http://127.0.0.1:8000/blog/post/' + document.title)
>>>>>>> New-Frontend
    post = await response.json()
    addPost()
    postStatis()

<<<<<<< HEAD
    let response2 = await fetch(`http://computerizr/blog/recent-posts/6`)
=======
    let response2 = await fetch(`http://127.0.0.1:8000/blog/recent-posts/6`)
>>>>>>> New-Frontend
    posts = await response2.json()
    addRecents()
}

function addPost() {
    let dateHolder = post.publish_date.slice(0, 10)
    let date = "";

    date = dateHolder.slice(8, 10) + "/" + dateHolder.slice(5, 7) + "/" + dateHolder.slice(0, 4) 

    postTitle.innerText = post.title
    author.innerText = post.author
    dateSpan.innerText = date
    postText.innerHTML = post.body
    heroImage.src = "/" + post.image
}

function addRecents() {
    let fragmentDiv = document.createDocumentFragment()
    for (let i of posts) {
        let cardDiv = document.createElement("div")
        cardDiv.classList.add("post-card")
        cardDiv.innerHTML = `
            <img src="${i.image}" alt="post image" class="card__img">
            <div class="card__text">
                <h3 class="post-card__title" id="${i.title}">
                    ${i.title}
                </h3>
            </div>
        `

        fragmentDiv.appendChild(cardDiv)
    }
    recentsNav.appendChild(fragmentDiv)
    let titles = document.querySelectorAll(".post-card__title")
    titles.forEach(title => {
        title.addEventListener("click", redirectUrl)})
}

function redirectUrl(e) {
    e.preventDefault()
<<<<<<< HEAD
    window.location.href = "http://computerizr" + `/post/${e.target.id}`
=======
    window.location.href = "http://127.0.0.1:8000/" + `/post/${e.target.id}`
>>>>>>> New-Frontend
}

function postStatis() {
    statisDiv.innerHTML = `
    <div class="impression">
        <p>Did you like this article? :</p>
        <button class="like">
            <img src="/Computerizer/static/frontend/media/thumbs-up-solid.svg" alt="like">
            <span>${post.likes}</span>
        </button>
        <button class="dislike">
            <img src="/Computerizer/static/frontend/media/thumbs-down-solid.svg" alt="dislike">
            <span>${post.dislikes}</span>
        </button>
    </div>
    <div class="views">
        <p>Number of views on this article: <span>${post.views}</span></p>
    </div>
    `
<<<<<<< HEAD
=======

>>>>>>> New-Frontend
}

div()