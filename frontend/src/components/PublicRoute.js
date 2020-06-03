import React, { Component } from 'react';
import { Route, Redirect } from 'react-router-dom'
import API from '../api'


class PublicRoute extends Component {
    constructor(props) {
        super(props)
        this.state = { 'loggedIn': true , 'isChecking': true}
    }
    async componentDidMount() {
        var isLoggedIn = await API.checkLoggedIn()
        this.setState({ 'loggedIn':  isLoggedIn, 'isChecking': false})
    }

    async componentWillUnmount() {
        
    }
    render() {
        if(this.state.isChecking) {
            return null
        }
        return (
            this.state.loggedIn === false
              ? <Route {... this.props} />
              : <Redirect to='/dashboard' />
        )
    }
}
export default PublicRoute;