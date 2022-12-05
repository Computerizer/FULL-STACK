let posts = ""
let sales = ""
let readMoreBtn = ""
let fetchPostNum = 7
const sliderDiv = document.querySelector(".slider")
const sliderMainDiv = document.querySelector(".slider__main")
const sliderNavDiv = document.querySelector(".slider__nav")
const postsDiv = document.querySelector(".posts")
const loadMoreBtn = document.querySelector(".load-more")



// Feching data & main function
let mainFunc = async () => {
    let response = await fetch(`http://127.0.0.1:8000/blog/recent-posts/${fetchPostNum}`)
    console.log(response)
    posts = await response.json()
    console.log(posts)
    slider()
    addRecentPossts()
    let response2 = await fetch('http://127.0.0.1:8000/blog/sales/5')
    sales = await response2.json()
    addSales()
    addListeners()
}


// listener functions
function addListeners() {
    sliderNavDiv.addEventListener("click", selectPsot)
    loadMoreBtn.addEventListener('click', loadMore)
    readMoreBtn = document.querySelectorAll(".read_more")
    readMoreBtn.forEach(btn => {
        btn.addEventListener("click", redirectUrl)
    });
}

function selectPsot(e) {
    if (e.target.nodeName === 'H3') {
        sliderMainDiv.querySelector(".post-title").textContent = posts[e.target.id].title
        sliderMainDiv.querySelector("button").value = posts[e.target.id].title
        sliderMainDiv.querySelector(".header__text").innerHTML = posts[e.target.id].description
        sliderMainDiv.style.backgroundImage = `url('${posts[e.target.id].image}')`
    }
}

function loadMore(e) {
    e.preventDefault
    addRecentPossts(fetchPostNum)
    const loadMoreBtn = document.querySelector(".load-more")
    loadMoreBtn.style.display = "none"
}

function redirectUrl(e) {
    e.preventDefault()
    window.location.href = "http://127.0.0.1:8000/" + `/post/${e.target.value}`
}


// Components render

function slider() {
    let fragmentDiv = document.createDocumentFragment()
    for (let i = 0; i < 4; i++) {
        let cardDiv = document.createElement("div")
        cardDiv.classList.add("post-card")
        cardDiv.innerHTML = `
            <div class="card-text">
                <div class="head">
                    <i class="material-icons">
                        format_align_justify
                    </i>
                    <h3 class="post-card__title" id="${i}">
                        ${posts[i].title}
                    </h3>
                </div>
                <p>${posts[i].description}</p>
            </div>
        `
        fragmentDiv.appendChild(cardDiv)
    }
    sliderNavDiv.appendChild(fragmentDiv)

    sliderMainDiv.firstElementChild.innerHTML = `
    <div class="text">
        <h1 class="post-title">
            ${posts[0].title}
        </h1>
        <p class="header__text">
            ${posts[0].description}
        </p>
    </div>
    <button type="submit" value="${posts[0].title}" class="read_more">Read More</button>
    `
    sliderMainDiv.style.backgroundImage = `url('${posts[0].image}')`
}

function addRecentPossts(n = 3) {
    let m = n - 3
    const postsFrag = document.createDocumentFragment()
    for (let i = m; i < n; i++) {
        let postDiv = document.createElement("div")
        postDiv.classList.add("post")
        
        postDiv.innerHTML = `
        <hr>
        <div class="post__body" >
            <img src="${posts[i].image}" alt="img">
            <div class="post__info">
                <div class="post__info__body">
                    <h3 class="post__title">
                        ${posts[i].title}
                    </h3>
                    <span class="auther">
                        ${posts[i].author}
                    </span>
                    <p class="post__prev">
                        ${posts[i].description}
                    </p>
                </div>
                <div class="post__action">
                    <span class="time">${posts[i].add_date.slice(0, 10)}</span>
                    <button class="read_more" value="${posts[i].title}">Read more</button>
                </div>
            </div>
        </div>
        `
        postsFrag.appendChild(postDiv)
    }
    postsDiv.appendChild(postsFrag)
    readMoreBtn = document.querySelectorAll(".read_more")
    readMoreBtn.forEach(btn => {
        btn.addEventListener("click", redirectUrl)
    });
}

function addSales() {
    for (part of sales) {
        let partDiv = document.querySelector(`.${part.part}`)
        partDiv.querySelector("a").href = part.link
        partDiv.querySelector("p").innerText = part.body
        partDiv.querySelector("img").src = part.image
    }
}

// Start the program
mainFunc()



