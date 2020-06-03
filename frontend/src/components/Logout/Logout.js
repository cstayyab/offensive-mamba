import React, { Component} from 'react';


class Logout extends Component {
    constructor(props) {
        super(props)
        localStorage.removeItem('userToken')
        window.location.href = "/"
    }
    render() {
        return <></>
    }
}

export default Logout