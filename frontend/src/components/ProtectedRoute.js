import React, { Component } from 'react';
import { Route, Redirect } from 'react-router-dom'
import API from '../api'


class PrivateRoute extends Component {
    constructor(props) {
        super(props)
        this.state = { 'loggedIn': false , 'isChecking': true}
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
            this.state.loggedIn === true
              ? <Route {... this.props} />
              : <Redirect to='/login' />
        )
    }
}
export default PrivateRoute;