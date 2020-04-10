import React, { Component } from 'react';
import { Container, Row, Col, Table, Alert, CardHeader, Card, CardBody, Input, InputGroup, Button, FormFeedback } from 'reactstrap'
import API from '../../api'
import './AgentSettings.css'

class AgentSettings extends Component {
    constructor(props) {
        super(props)
        this.state = {
            ipaddress: "",
            errors: {

            },
            error: null,
            message: null,
            systems: []
        }
        this.handleChange = this.handleChange.bind(this)
        this.validateIP = this.validateIP.bind(this)
        this.addSystem = this.addSystem.bind(this)
        this.removeSystem = this.removeSystem.bind(this)
    }

    handleChange(e) {
        e.persist()
        if (e.target.value !== this.state[e.target.name]) {
            var data = { errors: {}, error: {}, message: null }
            data[e.target.name] = e.target.value
            this.setState(data, () => {
                if (e.target.name === "ipaddress") {
                    this.validateIP()
                }
            })

        }


    }

    validateIP() {
        var regexIP = /^((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\.(?!$)|$)){4}$/
        var errors = this.state.errors
        if (this.state.ipaddress.match(regexIP) === null) {
            errors['ipaddress'] = "Invalid IP Address!!"
            this.setState({ errors: errors })
        } else {
            errors['ipaddress'] = ""
            this.updateIPPool().then(() => {
                if (this.state.systems.includes(this.state.ipaddress)) {
                    errors = this.state.errors
                    errors['ipaddress'] = "This IP Address is already registered in your IP Pool."
                    this.setState({ errors: errors })
                }
            })

        }

    }

    async componentDidMount() {
        await this.updateIPPool()

    }

    async addSystem() {
        var response = await API.addLocalSystem(this.state.ipaddress)
        if (response.success) {
            this.setState({ message: response.message, ipaddress: "" })
            setTimeout(() => {
                this.setState({ message: "" })
            }, 2000)
        } else {
            var errors = this.state.errors
            errors['ipaddress'] = response.error
            this.setState({ errors: errors })
        }
        this.updateIPPool()
    }

    async removeSystem(ipaddress) {
        if (this.state.systems.includes(ipaddress)) {
            var response = await API.removeLocalSystem(ipaddress)
            if (response.success) {
                this.setState({ "removedMessage": response.message })
                setTimeout(() => {
                    this.setState({ "removedMessage": "" })
                }, 2000)
            } else {
                this.setState({ "removedError": response.error })
                setTimeout(() => {
                    this.setState({ "removedError": "" })
                }, 2000)
            }
            this.updateIPPool()
        }
    }
    async updateIPPool() {
        var response = await API.getAllLocalSystems()
        if (response.success) {
            this.setState({ systems: response.data })
        }
    }

    render() {
        var tableData = (this.state.systems.length > 0) ? (
            <Table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>IP Address</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {this.state.systems.map((element, i) => {
                        return (<tr key={i}>
                            <th scope="row">{i + 1}</th>
                            <td>{element}</td>
                            <td><Button className="mx-1">Edit</Button><Button className="mx-1" onClick={() => { this.removeSystem(element) }}>Remove</Button></td>
                        </tr>)
                    })}
                </tbody>
            </Table>
        ) : <Alert color="info">You haven't added any system to your IP Pool.</Alert>;
        var messageAlert = (this.state.message) ? (
            <Alert color="success">{this.state.message}</Alert>
        ) : null
        var removedAlert = (this.state.removedMessage) ? (
            <Alert color="success">{this.state.removedMessage}</Alert>
        ) : null
        var removedError = (this.state.removedError) ? (
            <Alert color="danger">{this.state.removedError}</Alert>
        ) : null

        return (
            <Container fluid={true}>
                <Row>
                    <Col>
                        <h1 className="border-bottom">Agent Settings</h1>
                        <div><small>Manage your Local IP Pool</small></div>
                    </Col>
                </Row>
                <Container className="main">
                    {removedAlert}
                    {removedError}
                    {tableData}
                    <Row className="mt-4">
                        <Col sm="6">
                            <Card>
                                <CardHeader>Add New System</CardHeader>
                                <CardBody>
                                    {messageAlert}
                                    <InputGroup>
                                        <Input type="text" placeholder="Enter IP Address" onChange={this.handleChange} name="ipaddress" id="ipaddress" invalid={this.state.ipaddress !== "" && !!this.state.errors.ipaddress} value={this.state.ipaddress} />
                                        <FormFeedback invalid={'true'}>
                                            {(this.state.errors.ipaddress) ? this.state.errors.ipaddress : null}
                                        </FormFeedback>
                                    </InputGroup>
                                    <Row className="mt-2">
                                        <Col><Button className="float-right" onClick={this.addSystem}>Add</Button>
                                        </Col>
                                    </Row>
                                </CardBody>
                            </Card>
                        </Col>
                    </Row>
                </Container>
            </Container>

        )
    }
}

export default AgentSettings;